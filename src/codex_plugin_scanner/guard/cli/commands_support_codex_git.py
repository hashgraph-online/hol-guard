"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

from ..runtime.git_pathspecs import (
    GitPathspecResolution as _GitPathspecResolution,
)
from ..runtime.git_pathspecs import (
    git_literal_file_selection as _git_literal_file_selection,
)
from ..runtime.git_pathspecs import (
    git_literal_pathspec_path as _git_literal_pathspec_path,
)
from ..runtime.git_pathspecs import (
    git_pathspec_is_supported as _git_pathspec_is_supported,
)
from ..runtime.git_pathspecs import (
    resolve_git_pathspecs as _resolve_git_pathspecs,
)

if TYPE_CHECKING:
    from .commands_support_codex_commands import (
        _CODEX_GIT_DIFF_BOOLEAN_OPTIONS,
        _CODEX_GIT_DIFF_DISALLOWED_OPTIONS,
        _CODEX_GIT_DIFF_OPTIONAL_VALUE_OPTIONS,
        _CODEX_GIT_DIFF_VALUE_OPTIONS,
        _CODEX_GIT_GLOBAL_VALUE_FLAGS,
        _CODEX_SAFE_GIT_GLOBAL_BOOLEAN_FLAGS,
        _CodexSedReadOnlyArgs,
    )
    from .commands_support_codex_git_config import _git_repo_diff_helpers_are_unconfigured
    from .commands_support_codex_paths import _codex_search_target_is_source_like


from ._commands_shared import *
from .commands_parser_helpers import *

_GIT_PATHSPEC_GLOBAL_MODES = frozenset(
    {"--glob-pathspecs", "--literal-pathspecs", "--no-literal-pathspecs", "--noglob-pathspecs"}
)


def _parse_codex_sed_read_only_args(args: list[str]) -> _CodexSedReadOnlyArgs | None:
    scripts: list[str] = []
    targets: list[str] = []
    skip_next_script = False
    after_option_terminator = False
    saw_print_suppression = False
    for arg in args:
        if skip_next_script:
            skip_next_script = False
            scripts.append(arg)
            continue
        if after_option_terminator:
            targets.append(arg)
            continue
        if arg == "--":
            after_option_terminator = True
            continue
        if arg in {"-i", "--in-place"} or arg.startswith(("-i", "--in-place=")):
            return None
        if arg == "-n" or arg == "--quiet" or arg == "--silent":
            saw_print_suppression = True
            continue
        if arg == "-e" or arg == "--expression":
            skip_next_script = True
            continue
        if arg.startswith("-e") and len(arg) > 2:
            scripts.append(arg[2:])
            continue
        if arg.startswith("--expression="):
            _, script = arg.split("=", 1)
            scripts.append(script)
            continue
        if arg.startswith("-"):
            return None
        if not scripts:
            scripts.append(arg)
            continue
        targets.append(arg)
    if skip_next_script or not scripts:
        return None
    return _CodexSedReadOnlyArgs(
        scripts=tuple(scripts),
        targets=tuple(targets),
        saw_print_suppression=saw_print_suppression,
    )


def _codex_count_arg_is_bounded(value: str) -> bool:
    normalized = value.strip()
    return bool(re.fullmatch(r"\d{1,6}", normalized))


def _git_grep_search_args(args: list[str]) -> list[str] | None:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "grep":
            return args[index + 1 :]
        if arg in _CODEX_GIT_GLOBAL_VALUE_FLAGS:
            index += 2
            continue
        if any(arg.startswith(f"{flag}=") for flag in _CODEX_GIT_GLOBAL_VALUE_FLAGS):
            index += 1
            continue
        if arg in _CODEX_SAFE_GIT_GLOBAL_BOOLEAN_FLAGS:
            index += 1
            continue
        return None
    return None


def _codex_git_diff_targets_are_source_like(args: list[str], *, cwd: Path | None, home_dir: Path | None) -> bool:
    invocation = _git_diff_invocation(args, cwd=cwd)
    if invocation is None:
        return False
    diff_args, effective_cwd, global_modes = invocation
    targets = _git_diff_pathspecs(diff_args, cwd=effective_cwd)
    if targets is None:
        return False
    literal_selection = _git_literal_file_selection(targets, cwd=effective_cwd)
    if literal_selection is not None:
        selected_paths = literal_selection
        policy_root = effective_cwd
    else:
        resolution = _resolve_git_pathspecs(targets, cwd=effective_cwd, global_modes=global_modes)
        if not resolution.complete or not resolution.resolved_paths or resolution.repository_root is None:
            return False
        selected_paths = resolution.resolved_paths
        policy_root = resolution.repository_root
    return (
        bool(selected_paths)
        and all(
            _codex_search_target_is_source_like(str(target), cwd=policy_root, home_dir=home_dir)
            for target in selected_paths
        )
        and _git_diff_external_helpers_are_disabled_or_unconfigured(diff_args, cwd=effective_cwd)
    )


def _codex_git_diff_selection_identity(args: list[str], *, cwd: Path | None) -> str | None:
    invocation = _git_diff_invocation(args, cwd=cwd)
    if invocation is None:
        return None
    diff_args, effective_cwd, global_modes = invocation
    pathspecs = _git_diff_pathspecs(diff_args, cwd=effective_cwd)
    if pathspecs is None:
        return None
    resolution = _resolve_git_pathspecs(pathspecs, cwd=effective_cwd, global_modes=global_modes)
    return resolution.selection_identity


def _git_diff_args(args: list[str]) -> list[str] | None:
    invocation = _git_diff_invocation(args, cwd=None)
    return invocation[0] if invocation is not None else None


def _git_diff_invocation(
    args: list[str],
    *,
    cwd: Path | None,
) -> tuple[list[str], Path | None, tuple[str, ...]] | None:
    index = 0
    effective_cwd = cwd
    global_modes: list[str] = []
    while index < len(args):
        arg = args[index]
        if arg == "diff":
            return args[index + 1 :], effective_cwd, tuple(global_modes)
        if arg == "-C":
            if index + 1 >= len(args):
                return None
            directory = Path(args[index + 1])
            effective_cwd = directory if directory.is_absolute() or effective_cwd is None else effective_cwd / directory
            index += 2
            continue
        if arg.startswith("-C") and len(arg) > 2:
            directory = Path(arg[2:])
            effective_cwd = directory if directory.is_absolute() or effective_cwd is None else effective_cwd / directory
            index += 1
            continue
        if arg in _GIT_PATHSPEC_GLOBAL_MODES:
            global_modes.append(arg)
            index += 1
            continue
        if arg in _CODEX_SAFE_GIT_GLOBAL_BOOLEAN_FLAGS:
            index += 1
            continue
        return None
    return None


def _git_diff_path_args(args: list[str]) -> list[str]:
    pathspecs = _git_diff_pathspecs(args, cwd=None)
    return list(pathspecs) if pathspecs is not None else []


def _git_diff_pathspecs(args: list[str], *, cwd: Path | None) -> tuple[str, ...] | None:
    paths: list[str] = []
    index = 0
    after_path_separator = False
    while index < len(args):
        arg = args[index]
        if after_path_separator:
            paths.append(arg)
            index += 1
            continue
        if arg == "--":
            after_path_separator = True
            index += 1
            continue
        if arg in _CODEX_GIT_DIFF_DISALLOWED_OPTIONS or any(
            arg.startswith(f"{option}=") for option in _CODEX_GIT_DIFF_DISALLOWED_OPTIONS
        ):
            return None
        if arg in _CODEX_GIT_DIFF_OPTIONAL_VALUE_OPTIONS:
            index += 1
            continue
        if any(arg.startswith(f"{option}=") for option in _CODEX_GIT_DIFF_OPTIONAL_VALUE_OPTIONS):
            index += 1
            continue
        if arg in _CODEX_GIT_DIFF_VALUE_OPTIONS:
            if index + 1 >= len(args) or args[index + 1].startswith("-"):
                return None
            index += 2
            continue
        if any(arg.startswith(f"{option}=") for option in _CODEX_GIT_DIFF_VALUE_OPTIONS):
            index += 1
            continue
        if arg in _CODEX_GIT_DIFF_BOOLEAN_OPTIONS:
            index += 1
            continue
        if re.fullmatch(r"-U\d{1,6}", arg):
            index += 1
            continue
        if re.fullmatch(r"(?:-G|-S).+", arg):
            index += 1
            continue
        if arg.startswith("-"):
            return None
        candidate = Path(arg)
        if arg.startswith(":") or any(character in arg for character in "*?["):
            return None
        if cwd is not None and (candidate if candidate.is_absolute() else cwd / candidate).exists():
            return None
        if _git_diff_operand_is_revision(arg):
            index += 1
            continue
        return None
    return tuple(paths)


def _git_diff_operand_is_revision(value: str) -> bool:
    return bool(
        value == "HEAD"
        or value == "@"
        or value.startswith(("HEAD~", "HEAD^", "@{", "refs/"))
        or ".." in value
        or re.fullmatch(r"[0-9a-fA-F]{7,64}", value)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value)
    )


def _git_diff_external_helpers_are_disabled_or_unconfigured(args: list[str], *, cwd: Path | None) -> bool:
    has_no_ext_diff = "--no-ext-diff" in args
    has_no_textconv = "--no-textconv" in args
    if has_no_ext_diff and has_no_textconv:
        return True
    return _git_repo_diff_helpers_are_unconfigured(cwd)


__all__ = [
    "_GitPathspecResolution",
    "_codex_count_arg_is_bounded",
    "_codex_git_diff_selection_identity",
    "_codex_git_diff_targets_are_source_like",
    "_git_diff_args",
    "_git_diff_external_helpers_are_disabled_or_unconfigured",
    "_git_diff_invocation",
    "_git_diff_path_args",
    "_git_diff_pathspecs",
    "_git_grep_search_args",
    "_git_literal_file_selection",
    "_git_literal_pathspec_path",
    "_git_pathspec_is_supported",
    "_parse_codex_sed_read_only_args",
    "_resolve_git_pathspecs",
]
