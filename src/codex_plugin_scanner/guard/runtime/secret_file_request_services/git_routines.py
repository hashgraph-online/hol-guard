"""Safe routine Git command recognition."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from ..compound_git_inspection import (
    canonical_home_git_c_path,
    is_low_risk_standalone_git_routine,
    is_safe_standalone_git_object_existence_query,
)
from ..git_execution_safety import (
    git_binary_path_is_trusted,
    git_config_routing_environment_is_clean,
    trusted_git_binary_for_cwd,
)
from ..shell_execution_context import model_shell_execution_context
from .shell_tokenization import _iter_shell_command_segments, _shell_segment_primary_command
from .tool_action_requests import (
    _git_status_args_are_read_only,
    _git_status_has_execution_free_config,
    _safe_git_status_cd_target,
)


def _looks_like_safe_standalone_git_routine(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None = None,
) -> bool:
    if any(marker in command_text for marker in ("$(", "`", "<(", ">(", ";", "|", "\n")):
        return False
    if "&" in command_text:
        return False
    if cwd is None:
        return False
    try:
        execution_cwd = cwd.resolve()
    except (OSError, RuntimeError):
        return False
    if is_safe_standalone_git_object_existence_query(command_text, cwd=execution_cwd):
        return True
    context = model_shell_execution_context(
        command_text,
        cwd=execution_cwd,
        workspace_root=execution_cwd,
    )
    trusted_home = home_dir if canonical_home_git_c_path(command_text) is not None else None
    return is_low_risk_standalone_git_routine(context, home_dir=trusted_home)


def _looks_like_safe_git_status_command(
    command_text: str,
    parts: list[str],
    *,
    cwd: Path | None,
) -> bool:
    if any(marker in command_text for marker in ("$(", "`", "<(", ">(")):
        return False
    segments = _iter_shell_command_segments(parts)
    if not segments:
        return False
    saw_status = False
    try:
        effective_cwd = (cwd or Path.cwd()).resolve()
    except (OSError, RuntimeError):
        return False
    for segment in segments:
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index != 0:
            return False
        executable = segment[command_index]
        if "/" in executable or "\\" in executable:
            return False
        args = segment[command_index + 1 :]
        next_cwd = _safe_git_status_cd_target(command_name, args, cwd=effective_cwd)
        if next_cwd is not None:
            effective_cwd = next_cwd
            continue
        if command_name != "git" or not _git_status_args_are_read_only(args):
            return False
        if not _git_status_has_execution_free_config(effective_cwd):
            return False
        saw_status = True
    return saw_status


def _looks_like_safe_git_branch_switch_command(
    command_text: str,
    parts: list[str],
    *,
    cwd: Path | None,
) -> bool:
    if any(marker in command_text for marker in ("$(", "`", "<(", ">(", ";", "|", "<", ">")):
        return False
    if "&" in command_text.replace("&&", ""):
        return False
    segments = _iter_shell_command_segments(parts)
    if not segments:
        return False
    try:
        effective_cwd = (cwd or Path.cwd()).resolve()
    except (OSError, RuntimeError):
        return False
    saw_switch = False
    for segment in segments:
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index != 0:
            return False
        executable = segment[command_index]
        if "/" in executable or "\\" in executable:
            return False
        args = segment[command_index + 1 :]
        next_cwd = _safe_git_status_cd_target(command_name, args, cwd=effective_cwd)
        if next_cwd is not None:
            effective_cwd = next_cwd
            continue
        if command_name != "git" or saw_switch or not _git_local_branch_switch_is_safe(args, cwd=effective_cwd):
            return False
        saw_switch = True
    return saw_switch


def _git_local_branch_switch_is_safe(args: list[str], *, cwd: Path) -> bool:
    if len(args) != 2 or args[0] not in {"checkout", "switch"}:
        return False
    branch = args[1]
    if not branch or branch.startswith("-") or branch in {".", ".."}:
        return False
    git_path = shutil.which("git")
    if git_path is None:
        return False
    try:
        resolved_git = Path(git_path).resolve()
        execution_cwd = cwd.resolve()
    except (OSError, RuntimeError):
        return False
    if not git_binary_path_is_trusted(resolved_git, cwd=execution_cwd):
        return False
    try:
        branch_result = subprocess.run(
            [str(resolved_git), "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}"],
            cwd=execution_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
        execution_config = subprocess.run(
            [
                str(resolved_git),
                "config",
                "--null",
                "--get-regexp",
                r"^(core\.fsmonitor|filter\..*\.(clean|smudge|process)|submodule\..*\.update|submodule\.recurse)$",
            ],
            cwd=execution_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
        hook_result = subprocess.run(
            [str(resolved_git), "rev-parse", "--git-path", "hooks/post-checkout"],
            cwd=execution_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
        git_dir_result = subprocess.run(
            [str(resolved_git), "rev-parse", "--absolute-git-dir"],
            cwd=execution_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if branch_result.returncode != 0 or execution_config.returncode not in {0, 1}:
        return False
    if execution_config.returncode == 0 and not _git_checkout_execution_config_is_safe(
        execution_config.stdout,
        cwd=execution_cwd,
    ):
        return False
    if execution_config.returncode == 1 and execution_config.stdout:
        return False
    if hook_result.returncode != 0 or git_dir_result.returncode != 0:
        return False
    hook_path = Path(hook_result.stdout.strip())
    if not hook_path.is_absolute():
        hook_path = execution_cwd / hook_path
    try:
        hook_path = hook_path.resolve()
        git_dir = Path(git_dir_result.stdout.strip()).resolve(strict=True)
        if hook_path.is_relative_to(execution_cwd) and not hook_path.is_relative_to(git_dir):
            return False
        return not hook_path.exists() or (os.name != "nt" and not os.access(hook_path, os.X_OK))
    except (OSError, RuntimeError):
        return False


def _git_checkout_execution_config_is_safe(config_output: str, *, cwd: Path) -> bool:
    entries: dict[str, str] = {}
    for entry in config_output.split("\0"):
        if not entry:
            continue
        key, separator, value = entry.partition("\n")
        if not separator:
            return False
        entries[key.casefold()] = value
    if not entries:
        return True
    fsmonitor = entries.pop("core.fsmonitor", None)
    if fsmonitor is not None and fsmonitor.strip().casefold() not in {"0", "false", "no", "off"}:
        return False
    if not entries:
        return True
    allowed_lfs_entries = {
        "filter.lfs.clean": "git-lfs clean -- %f",
        "filter.lfs.smudge": "git-lfs smudge -- %f",
        "filter.lfs.process": "git-lfs filter-process",
    }
    if any(allowed_lfs_entries.get(key) != value for key, value in entries.items()):
        return False
    git_lfs_path = shutil.which("git-lfs")
    if git_lfs_path is None:
        return False
    try:
        return git_binary_path_is_trusted(Path(git_lfs_path).resolve(), cwd=cwd)
    except (OSError, RuntimeError):
        return False


def _read_only_git_invocation(args: list[str], *, cwd: Path) -> tuple[str, Path] | None:
    if not args:
        return None
    operation_index = 0
    git_cwd = cwd
    if args[0] == "-C":
        if len(args) < 3:
            return None
        target = Path(args[1]).expanduser()
        try:
            target = (target if target.is_absolute() else cwd / target).resolve(strict=True)
            target.relative_to(cwd.resolve())
        except (OSError, RuntimeError, ValueError):
            return None
        if not target.is_dir():
            return None
        git_cwd = target
        operation_index = 2
    elif args[0].startswith("-"):
        return None
    return args[operation_index].casefold(), git_cwd


def _git_log_has_execution_free_config(
    cwd: Path,
    *,
    git_binary: Path | None = None,
) -> bool:
    if any(os.environ.get(key, "").strip() not in {"", "cat"} for key in ("GIT_PAGER", "PAGER")):
        return False
    if not git_config_routing_environment_is_clean():
        return False
    try:
        execution_cwd = cwd.resolve()
    except (OSError, RuntimeError):
        return False
    resolved_git = git_binary or trusted_git_binary_for_cwd(execution_cwd)
    if resolved_git is None:
        return False
    for key in ("core.pager", "pager.log"):
        try:
            result = subprocess.run(
                [str(resolved_git), "config", "--null", "--get-all", key],
                cwd=execution_cwd,
                check=False,
                capture_output=True,
                text=True,
                timeout=1,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        if result.returncode == 1 and not result.stdout:
            continue
        if result.returncode != 0:
            return False
        values = [value.strip() for value in result.stdout.split("\0") if value.strip()]
        if any(value != "cat" for value in values):
            return False
    return True


__all__ = [
    "_git_checkout_execution_config_is_safe",
    "_git_local_branch_switch_is_safe",
    "_git_log_has_execution_free_config",
    "_looks_like_safe_git_branch_switch_command",
    "_looks_like_safe_git_status_command",
    "_looks_like_safe_standalone_git_routine",
    "_read_only_git_invocation",
]
