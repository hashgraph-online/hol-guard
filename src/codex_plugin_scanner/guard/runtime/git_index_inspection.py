"""Staged-index Git inspection recognition for allow and extension ownership."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Final, Literal

from .compound_git_inspection import (
    _git_show_has_execution_free_config,
    _safe_repository_path,
    is_low_risk_git_inspection_segment,
    is_low_risk_standalone_git_routine,
)
from .secret_file_request_services.shell_tokenization import _shell_segment_primary_command
from .shell_execution_context import ShellExecutionContext, ShellExecutionSegment, model_shell_execution_context

_CONTROL_PREFIXES: Final = frozenset({"!", "elif", "else", "fi", "if", "then"})
_ALLOWED_CONTROLS: Final = frozenset({"&&", "||", "|", ";", "\n"})
_RG_BOOLEAN_FLAGS: Final = frozenset({"--ignore-case", "--line-number", "--no-config", "-i", "-in", "-n", "-ni"})
_GIT_GLOBAL_FLAG_OPTIONS: Final = frozenset(
    {
        "--bare",
        "--literal-pathspecs",
        "--no-advice",
        "--no-lazy-fetch",
        "--no-optional-locks",
        "--no-pager",
        "--no-replace-objects",
        "--paginate",
        "-P",
        "-p",
    }
)
_GIT_GLOBAL_VALUE_OPTIONS: Final = frozenset(
    {"--config-env", "--exec-path", "--git-dir", "--namespace", "--super-prefix", "--work-tree", "-C", "-c"}
)
_EXECUTION_ROUTING_OPTIONS: Final = frozenset({"-c", "--config-env", "--exec-path"})
_CACHED_DIFF_KIND = Literal["owned", "routed"]
_MAX_SEGMENTS: Final = 32


def executable_tokens(tokens: tuple[str, ...]) -> tuple[str, ...] | None:
    """Strip shell reserved-word prefixes. Empty means a no-op such as fi."""

    index = 0
    while index < len(tokens) and tokens[index] in _CONTROL_PREFIXES:
        if tokens[index] == "fi" and len(tokens) != 1:
            return None
        index += 1
    return tokens[index:]


def _static_echo_arg_is_safe(arg: str) -> bool:
    if "`" in arg or "$(" in arg or "<(" in arg or ">(" in arg:
        return False
    return "$" not in arg.replace("$?", "")


def _index_scan_rg_args_are_safe(args: tuple[str, ...]) -> bool:
    """Accept stdin-only ripgrep with one inline pattern after a cached diff."""

    saw_pattern = False
    for arg in args:
        if arg in _RG_BOOLEAN_FLAGS:
            continue
        if not arg or arg.startswith("-"):
            return False
        if saw_pattern:
            return False
        if any(marker in arg for marker in ("$(", "`", "<(", ">(", "\x00")):
            return False
        saw_pattern = True
    return saw_pattern


def _tokens_are_cached_diff(tokens: tuple[str, ...]) -> bool:
    kind = cached_diff_kind(tokens)
    return kind == "owned"


def cached_diff_kind(tokens: tuple[str, ...]) -> _CACHED_DIFF_KIND | None:
    """Classify one segment as an owned or execution-routed cached diff."""

    stripped = executable_tokens(tokens)
    if not stripped:
        return None
    command_name, command_index = _shell_segment_primary_command(list(stripped))
    if command_name != "git" or command_index is None:
        return None
    args = stripped[command_index + 1 :]
    index = 0
    routed = False
    while index < len(args):
        token = args[index]
        option_name = token.partition("=")[0]
        if token in _GIT_GLOBAL_FLAG_OPTIONS:
            index += 1
            continue
        if token == "-c" or (token.startswith("-c") and not token.startswith("-C")):
            routed = True
            if token == "-c":
                if index + 1 >= len(args):
                    return None
                index += 2
                continue
            index += 1
            continue
        if option_name in _GIT_GLOBAL_VALUE_OPTIONS:
            if option_name in _EXECUTION_ROUTING_OPTIONS:
                routed = True
            if "=" in token:
                if not token.partition("=")[2]:
                    return None
                index += 1
                continue
            if index + 1 >= len(args):
                return None
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        if token != "diff":
            return None
        operands = args[index + 1 :]
        if "--cached" not in operands:
            return None
        return "routed" if routed else "owned"
    return None


def command_has_execution_routed_git_cached_diff(segments: tuple[tuple[str, ...], ...]) -> bool:
    """Return whether any cached-diff segment overrides Git execution routing."""

    return any(cached_diff_kind(tokens) == "routed" for tokens in segments)


def command_has_owned_git_cached_diff(segments: tuple[tuple[str, ...], ...]) -> bool:
    """Return whether the command contains a named cached-diff Guard can own."""

    if command_has_execution_routed_git_cached_diff(segments):
        return False
    return any(cached_diff_kind(tokens) == "owned" for tokens in segments)


def is_low_risk_git_index_inspection(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None = None,
) -> bool:
    """Recognize a repo-bound staged-index inspection, including if/then scans."""

    return index_inspection_execution_context(command_text, cwd=cwd, home_dir=home_dir) is not None


def index_inspection_execution_context(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None = None,
) -> ShellExecutionContext | None:
    """Return the modeled context when a staged-index scan is repo-bound."""

    if cwd is None:
        return None
    try:
        execution_cwd = cwd.resolve()
    except (OSError, RuntimeError):
        return None
    context = model_shell_execution_context(
        command_text,
        cwd=execution_cwd,
        workspace_root=execution_cwd,
        home_dir=home_dir,
    )
    if not _context_is_low_risk_git_index_inspection(context, home_dir=home_dir):
        return None
    return context


def _segment_has_mutating_redirection(tokens: tuple[str, ...]) -> bool:
    for token in tokens:
        if token in {">", ">>", ">|", "1>", "1>>", "1>|"}:
            return True
        if ">" in token and not token.startswith("--"):
            return True
    return False


def _flow_controls(controls: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(control for control in controls if control != "\n")


def _context_is_low_risk_git_index_inspection(
    context: ShellExecutionContext,
    *,
    home_dir: Path | None,
) -> bool:
    if not context.segments or len(context.segments) > _MAX_SEGMENTS:
        return False
    if not context.complete and context.reason_code != "shell_cwd_unresolved_syntax":
        return False
    saw_cached_diff = False
    previous_was_cached_diff = False
    for segment in context.segments:
        if any(control not in _ALLOWED_CONTROLS for control in (*segment.control_before, *segment.control_after)):
            return False
        tokens = executable_tokens(segment.tokens)
        if tokens is None:
            return False
        if not tokens:
            previous_was_cached_diff = False
            continue
        if _segment_has_mutating_redirection(segment.tokens):
            return False
        command_name, command_index = _shell_segment_primary_command(list(tokens))
        if command_name is None or command_index is None:
            return False
        executable = tokens[command_index]
        if "/" in executable or "\\" in executable:
            return False
        args = tokens[command_index + 1 :]
        if command_name == "git":
            if not _git_cached_diff_segment_is_safe(segment, tokens, home_dir=home_dir):
                return False
            saw_cached_diff = True
            previous_was_cached_diff = True
            continue
        if command_name == "echo":
            if not all(_static_echo_arg_is_safe(arg) for arg in args):
                return False
            previous_was_cached_diff = False
            continue
        if command_name == "rg":
            if _flow_controls(segment.control_before) != ("|",) or not previous_was_cached_diff:
                return False
            if not _index_scan_rg_args_are_safe(args):
                return False
            previous_was_cached_diff = False
            continue
        return False
    return saw_cached_diff


def owned_git_index_inspection_action_class(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> str | None:
    """Return the Git-protection action class for an unproven cached diff."""

    if "git" not in command_text or "diff" not in command_text or "--cached" not in command_text:
        return None
    parsing_cwd = cwd or home_dir or Path.cwd()
    context = model_shell_execution_context(
        command_text,
        cwd=parsing_cwd,
        workspace_root=parsing_cwd,
        home_dir=home_dir,
    )
    segment_tokens = tuple(segment.tokens for segment in context.segments)
    if command_has_execution_routed_git_cached_diff(segment_tokens):
        return None
    if not command_has_owned_git_cached_diff(segment_tokens):
        return None
    if cwd is not None and is_low_risk_git_index_inspection(command_text, cwd=cwd, home_dir=home_dir):
        return None
    if cwd is not None and is_low_risk_standalone_git_routine(context, home_dir=home_dir):
        return None
    return "git index inspection"


_SAFE_CACHED_DIFF_FLAGS: Final = frozenset({"--cached", "--check", "--stat", "--name-only", "--name-status", "HEAD"})


def _safe_exclude_pathspec(value: str) -> bool:
    if not value.startswith((":!", ":^")):
        return False
    remainder = value[2:]
    if not remainder or remainder.startswith((":", "/", "~")):
        return False
    return _safe_repository_path(remainder)


def _cached_diff_operands_are_safe(args: tuple[str, ...]) -> bool:
    if "--cached" not in args or len(args) > 20:
        return False
    if "--" not in args:
        return all(arg in _SAFE_CACHED_DIFF_FLAGS or arg == "--cached" for arg in args)
    separator = args.index("--")
    revisions = args[:separator]
    paths = args[separator + 1 :]
    if not paths or len(paths) > 16:
        return False
    if any(arg not in _SAFE_CACHED_DIFF_FLAGS for arg in revisions):
        return False
    return all(_safe_repository_path(path) or _safe_exclude_pathspec(path) for path in paths)


def _proof_cached_diff_tokens(tokens: tuple[str, ...]) -> tuple[str, ...]:
    command_name, command_index = _shell_segment_primary_command(list(tokens))
    if command_name != "git" or command_index is None:
        return ("git", "diff", "--cached", "--check")
    prefix = tokens[: command_index + 1]
    args = tokens[command_index + 1 :]
    if args[:1] == ("-C",) and len(args) >= 2:
        return (*prefix, "-C", args[1], "diff", "--cached", "--check")
    return (*prefix, "diff", "--cached", "--check")


def _git_cached_diff_segment_is_safe(
    segment: ShellExecutionSegment,
    tokens: tuple[str, ...],
    *,
    home_dir: Path | None,
) -> bool:
    if not _tokens_are_cached_diff(tokens):
        return False
    operands = git_diff_operands(tokens)
    if operands is None or not _cached_diff_operands_are_safe(operands):
        return False
    synthetic = replace(segment, tokens=_proof_cached_diff_tokens(tokens))
    repository_path = tokens[2] if tokens[:2] == ("git", "-C") and len(tokens) > 2 else None
    return is_low_risk_git_inspection_segment(
        synthetic,
        home_dir=home_dir,
    ) and _git_show_has_execution_free_config(synthetic, repository_path=repository_path)


def git_diff_operands(tokens: tuple[str, ...]) -> tuple[str, ...] | None:
    kind = cached_diff_kind(tokens)
    if kind != "owned":
        return None
    stripped = executable_tokens(tokens)
    if not stripped:
        return None
    command_name, command_index = _shell_segment_primary_command(list(stripped))
    if command_name != "git" or command_index is None:
        return None
    args = stripped[command_index + 1 :]
    index = 0
    while index < len(args):
        token = args[index]
        option_name = token.partition("=")[0]
        if token in _GIT_GLOBAL_FLAG_OPTIONS:
            index += 1
            continue
        if option_name in _GIT_GLOBAL_VALUE_OPTIONS:
            index += 1 if "=" in token else 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        if token != "diff":
            return None
        return args[index + 1 :]
    return None
