"""Conservative whole-command recognition for routine Git command chains."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Final

from .git_execution_safety import (
    git_config_routing_environment_is_clean,
    git_fetch_origin_has_execution_free_config,
    git_push_origin_has_execution_free_config,
    git_status_has_execution_free_config,
    trusted_git_binary_for_cwd,
)
from .shell_execution_context import ShellExecutionContext, ShellExecutionSegment

_REF: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}")
_REPOSITORY_PATH_COMPONENT: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
_BOUND: Final = 1000


def is_low_risk_compound_git_inspection(context: ShellExecutionContext) -> bool:
    """Recognize a deterministic leading-cd Git routine."""

    if not context.complete or len(context.segments) < 2:
        return False
    if not _leading_literal_cd(context.segments[0]):
        return False
    saw_git = False
    for index, segment in enumerate(context.segments[1:], start=1):
        if any(control not in {"&&", "|"} for control in (*segment.control_before, *segment.control_after)):
            return False
        command = segment.tokens[0] if segment.tokens else ""
        if command == "git":
            if not (is_low_risk_git_inspection_segment(segment) or is_low_risk_git_push_segment(segment)):
                return False
            saw_git = True
            continue
        if command == "echo":
            if not _safe_echo_segment(segment):
                return False
            continue
        if command in {"head", "tail"}:
            if not _safe_bound_segment(segment, previous=context.segments[index - 1]):
                return False
            continue
        return False
    return saw_git


def _leading_literal_cd(segment: ShellExecutionSegment) -> bool:
    return bool(
        not segment.control_before
        and segment.directory_operation == "cd"
        and len(segment.tokens) == 2
        and segment.tokens[0] == "cd"
    )


def is_low_risk_git_inspection_segment(segment: ShellExecutionSegment) -> bool:
    """Recognize one bounded Git refresh or inspection segment."""

    tokens = _without_stderr_merge(segment.tokens)
    if tokens is None or len(tokens) < 2:
        return False
    operation_index = 1
    repository_path: str | None = None
    if tokens[1] == "-C":
        if len(tokens) < 4 or not _safe_repository_path(tokens[2]):
            return False
        repository_path = tokens[2]
        operation_index = 3
    invocation_cwds = _git_invocation_cwds(segment, repository_path=repository_path)
    if invocation_cwds is None:
        return False
    execution_cwd, repository_cwd = invocation_cwds
    resolved_git = trusted_git_binary_for_cwd(execution_cwd)
    if resolved_git is None:
        return False
    operation = tokens[operation_index]
    args = tokens[operation_index + 1 :]
    if operation == "fetch":
        return bool(
            _safe_fetch_args(args)
            and git_fetch_origin_has_execution_free_config(
                repository_cwd,
                git_binary=resolved_git,
            )
        )
    if operation == "ls-remote":
        return bool(
            _safe_ls_remote_args(args)
            and git_fetch_origin_has_execution_free_config(
                repository_cwd,
                git_binary=resolved_git,
            )
        )
    if operation == "log":
        return _safe_bounded_log_args(args) and _git_log_has_execution_free_config(
            repository_cwd,
            git_binary=resolved_git,
        )
    if operation == "blame":
        return (
            _safe_blame_args(args)
            and _git_show_has_execution_free_config(segment, repository_path=repository_path)
            and _git_log_has_execution_free_config(
                repository_cwd,
                git_binary=resolved_git,
                pager_key="pager.blame",
            )
        )
    if operation == "status":
        return (
            bool(args)
            and all(_safe_status_arg(arg) for arg in args)
            and git_status_has_execution_free_config(repository_cwd, git_binary=resolved_git)
        )
    if operation == "branch":
        return _safe_branch_args(args) and _git_log_has_execution_free_config(
            repository_cwd,
            git_binary=resolved_git,
            pager_key="pager.branch",
        )
    if operation == "rev-parse":
        return _safe_rev_parse_args(args)
    if operation == "diff":
        return _safe_diff_args(args)
    if operation == "ls-files":
        return _safe_ls_files_args(args)
    if operation == "show":
        return _safe_show_args(args) and _git_show_has_execution_free_config(
            segment,
            repository_path=repository_path,
        )
    if operation == "worktree":
        return args == ("list", "--porcelain")
    return False


def is_low_risk_git_push_segment(segment: ShellExecutionSegment) -> bool:
    """Recognize one current-branch push to a verified GitHub origin."""

    tokens = _without_stderr_merge(segment.tokens)
    if (
        tokens is None
        or len(tokens) != 5
        or tokens[:3]
        not in {
            ("git", "push", "-u"),
            ("git", "push", "--set-upstream"),
        }
    ):
        return False
    if tokens[3] != "origin" or _safe_ref(tokens[4]) is False:
        return False
    invocation_cwds = _git_invocation_cwds(segment, repository_path=None)
    if invocation_cwds is None:
        return False
    execution_cwd, repository_cwd = invocation_cwds
    resolved_git = trusted_git_binary_for_cwd(execution_cwd)
    return bool(
        resolved_git is not None
        and git_push_origin_has_execution_free_config(
            repository_cwd,
            branch=tokens[4],
            git_binary=resolved_git,
        )
    )


def is_low_risk_standalone_git_routine(context: ShellExecutionContext) -> bool:
    """Recognize one bounded Git read or configured-origin ref refresh."""

    if not context.complete or len(context.segments) != 1:
        return False
    segment = context.segments[0]
    return bool(
        segment.tokens[:1] == ("git",)
        and not segment.control_before
        and not segment.control_after
        and is_low_risk_git_inspection_segment(segment)
    )


def _safe_rev_parse_args(args: tuple[str, ...]) -> bool:
    return args in {("--show-toplevel",), ("--show-prefix",), ("--is-inside-work-tree",)} or (
        len(args) == 1 and _safe_ref(args[0])
    )


def _safe_status_arg(value: str) -> bool:
    if value in {"--short", "--branch", "--porcelain", "--porcelain=v1"}:
        return True
    return bool(
        value.startswith("-") and not value.startswith("--") and len(value) > 1 and set(value[1:]) <= {"b", "s"}
    )


def _safe_bounded_log_args(args: tuple[str, ...]) -> bool:
    if len(args) == 3 and args[0] in {"-1", "-n1"} and args[1].startswith("--format="):
        return _safe_log_format(args[1][len("--format=") :]) and _safe_ref(args[2])
    if "--oneline" not in args or args.count("--oneline") != 1:
        return False
    bounds = [arg for arg in args if arg.startswith("-") and arg[1:].isdigit()]
    if len(bounds) != 1 or not 1 <= int(bounds[0][1:]) <= 100:
        return False
    refs = [arg for arg in args if arg not in {"--oneline", bounds[0]}]
    return len(refs) <= 1 and all(_safe_ref(ref) for ref in refs)


def _safe_fetch_args(args: tuple[str, ...]) -> bool:
    if args in {("origin", "--quiet"), ("--quiet", "origin")}:
        return True
    return len(args) == 2 and args[0] == "origin" and _safe_ref(args[1])


def _safe_ls_remote_args(args: tuple[str, ...]) -> bool:
    return bool(3 <= len(args) <= 12 and args[:2] == ("--heads", "origin") and all(_safe_ref(ref) for ref in args[2:]))


def _safe_branch_args(args: tuple[str, ...]) -> bool:
    if args in {("--show-current",), ("--list",)}:
        return True
    return bool(
        3 <= len(args) <= 12
        and args[:2] in {("-r", "--list"), ("--remotes", "--list")}
        and all(_safe_ref(ref) for ref in args[2:])
    )


def _safe_log_format(value: str) -> bool:
    return bool(value and len(value) <= 160 and re.fullmatch(r"(?:[^%\r\n]|%(?:H|h|cI|s|an|ae))+", value))


def _safe_blame_args(args: tuple[str, ...]) -> bool:
    if len(args) != 4 or args[0] != "-L" or args[2] != "--":
        return False
    match = re.fullmatch(r"([1-9][0-9]{0,5}),([1-9][0-9]{0,5})", args[1])
    if match is None:
        return False
    start, end = int(match.group(1)), int(match.group(2))
    return start <= end <= 100_000 and end - start <= 1000 and _safe_repository_path(args[3])


def _safe_repository_path(value: str) -> bool:
    if value == ".":
        return True
    if not value or len(value) > 512 or value.startswith(("/", "~")) or _dynamic(value):
        return False
    normalized = value[:-1] if value.endswith("/") else value
    components = normalized.split("/")
    if components[:1] == ["."]:
        components = components[1:]
    return bool(components) and all(
        component not in {"", ".", ".."} and _REPOSITORY_PATH_COMPONENT.fullmatch(component) is not None
        for component in components
    )


def _safe_diff_args(args: tuple[str, ...]) -> bool:
    if not args:
        return False
    if "--" not in args:
        return all(
            arg in {"--check", "--stat", "--name-only", "--name-status", "--cached", "HEAD"} or _safe_ref(arg)
            for arg in args
        )
    separator = args.index("--")
    revisions = args[:separator]
    paths = args[separator + 1 :]
    return (
        bool(paths)
        and all(
            arg in {"--check", "--stat", "--name-only", "--name-status", "--cached", "HEAD"} or _safe_ref(arg)
            for arg in revisions
        )
        and all(_safe_repository_path(path) for path in paths)
    )


def _safe_show_args(args: tuple[str, ...]) -> bool:
    if not args:
        return False
    allowed_options = {"--stat", "--oneline", "--name-only", "--name-status"}
    if "--" not in args:
        return all(arg in allowed_options or arg == "HEAD" or _safe_ref(arg) or _safe_object_path(arg) for arg in args)
    separator = args.index("--")
    revisions = args[:separator]
    paths = args[separator + 1 :]
    refs = tuple(arg for arg in revisions if arg not in allowed_options)
    return (
        bool(paths)
        and len(refs) == 1
        and (refs[0] == "HEAD" or _safe_ref(refs[0]))
        and all(arg in allowed_options or arg in refs for arg in revisions)
        and all(_safe_repository_path(path) for path in paths)
    )


def _git_show_has_execution_free_config(
    segment: ShellExecutionSegment,
    *,
    repository_path: str | None,
) -> bool:
    if segment.effective_cwd is None:
        return False
    if os.environ.get("GIT_EXTERNAL_DIFF", "").strip() or not git_config_routing_environment_is_clean():
        return False
    invocation_cwds = _git_invocation_cwds(segment, repository_path=repository_path)
    if invocation_cwds is None:
        return False
    execution_cwd, repository_cwd = invocation_cwds
    resolved_git = trusted_git_binary_for_cwd(execution_cwd)
    if resolved_git is None:
        return False
    try:
        result = subprocess.run(
            [
                str(resolved_git),
                "config",
                "--null",
                "--get-regexp",
                r"^(diff\..*\.(command|textconv)|diff\.external)$",
            ],
            cwd=repository_cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 1 and not result.stdout


def _git_invocation_cwds(
    segment: ShellExecutionSegment,
    *,
    repository_path: str | None,
) -> tuple[Path, Path] | None:
    if segment.effective_cwd is None:
        return None
    try:
        execution_cwd = segment.effective_cwd.resolve()
        repository_cwd = (execution_cwd / repository_path).resolve() if repository_path is not None else execution_cwd
    except (OSError, RuntimeError):
        return None
    return (execution_cwd, repository_cwd) if repository_cwd.is_dir() else None


def _git_log_has_execution_free_config(
    cwd: Path,
    *,
    git_binary: Path,
    pager_key: str = "pager.log",
) -> bool:
    if any(os.environ.get(key, "").strip() not in {"", "cat"} for key in ("GIT_PAGER", "PAGER")):
        return False
    if not git_config_routing_environment_is_clean():
        return False
    for key in ("core.pager", pager_key):
        try:
            result = subprocess.run(
                [str(git_binary), "config", "--null", "--get-all", key],
                cwd=cwd,
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


def _safe_ls_files_args(args: tuple[str, ...]) -> bool:
    allowed = {"--exclude-standard", "--others"}
    return bool(args) and len(args) == len(set(args)) and set(args) <= allowed and "--others" in args


def _safe_object_path(value: str) -> bool:
    if value.count(":") != 1:
        return False
    revision, path = value.split(":", 1)
    return _safe_ref(revision) and _safe_repository_path(path)


def _without_stderr_merge(tokens: tuple[str, ...]) -> tuple[str, ...] | None:
    safe_redirects = {"2>&1", "2>/dev/null"}
    redirects = tuple(token for token in tokens if token in safe_redirects)
    if len(redirects) > 1:
        return None
    if any(any(marker in token for marker in (">", "<")) and token not in safe_redirects for token in tokens):
        return None
    return tuple(token for token in tokens if token not in safe_redirects)


def _safe_ref(value: str) -> bool:
    if re.fullmatch(r"HEAD~[1-9][0-9]{0,3}", value):
        return True
    return _REF.fullmatch(value) is not None and ".." not in value and not value.endswith((".", "/"))


def _safe_echo_segment(segment: ShellExecutionSegment) -> bool:
    return bool(
        len(segment.tokens) >= 2
        and segment.control_before == ("&&",)
        and segment.control_after == ("&&",)
        and all(token not in {"-e", "-E", "-n"} and not _dynamic(token) for token in segment.tokens[1:])
    )


def _safe_bound_segment(segment: ShellExecutionSegment, *, previous: ShellExecutionSegment) -> bool:
    if segment.control_before != ("|",) or len(segment.tokens) != 2:
        return False
    if not previous.tokens or previous.tokens[0] != "git" or previous.control_after != ("|",):
        return False
    count = segment.tokens[1]
    if not count.startswith("-") or not count[1:].isdigit():
        return False
    return 1 <= int(count[1:]) <= _BOUND


def _dynamic(value: str) -> bool:
    return any(marker in value for marker in ("$", "`", "<", ">", "|", ";", "&", "\x00"))


__all__ = (
    "is_low_risk_compound_git_inspection",
    "is_low_risk_git_inspection_segment",
    "is_low_risk_git_push_segment",
    "is_low_risk_standalone_git_routine",
)
