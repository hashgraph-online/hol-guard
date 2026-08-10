"""Structural recognition for bounded read-only Git ancestry audits."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from .compound_git_inspection import git_log_has_execution_free_config
from .git_execution_safety import trusted_git_binary_for_cwd
from .shell_execution_context import ShellExecutionContext, ShellExecutionSegment, model_shell_execution_context

_COMMIT_ID: Final = re.compile(r"[0-9A-Fa-f]{7,40}")
_VARIABLE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,31}")
_MAX_COMMITS: Final = 32
_MAX_PID_BYTES: Final = 32


def is_read_only_git_ancestry_audit(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path,
) -> bool:
    """Accept one literal commit loop with optional bounded local status reads."""

    initial_root = cwd or home_dir
    context = model_shell_execution_context(
        command_text,
        cwd=initial_root,
        workspace_root=initial_root,
        home_dir=home_dir,
    )
    if not context.complete or len(context.segments) < 6:
        return False
    workspace_root = _leading_workspace_root(context)
    if workspace_root is None:
        return False
    if not _is_within(workspace_root, home_dir) and not _is_within(workspace_root, initial_root):
        return False
    segments = context.segments
    index = 1
    if _is_static_echo(segments[index], before="&&", after="&&"):
        index += 1
    loop_end = _literal_ancestry_loop_end(segments, index=index, workspace_root=workspace_root)
    if loop_end is None:
        return False
    suffix = segments[loop_end:]
    return not suffix or _safe_status_suffix(suffix, workspace_root=workspace_root)


def _leading_workspace_root(context: ShellExecutionContext) -> Path | None:
    segment = context.segments[0]
    if (
        segment.tokens[:1] != ("cd",)
        or len(segment.tokens) != 2
        or segment.control_before
        or segment.control_after != ("&&",)
        or segment.directory_operation != "cd"
        or len(context.segments) < 2
    ):
        return None
    root = context.segments[1].effective_cwd
    if root is None:
        return None
    try:
        return root.resolve(strict=True)
    except OSError:
        return None


def _literal_ancestry_loop_end(
    segments: tuple[ShellExecutionSegment, ...],
    *,
    index: int,
    workspace_root: Path,
) -> int | None:
    if index + 4 >= len(segments):
        return None
    start, query, yes, no, end = segments[index : index + 5]
    if len(start.tokens) < 4 or start.tokens[0] != "for" or start.tokens[2] != "in":
        return None
    variable = start.tokens[1]
    commits = start.tokens[3:]
    if (
        _VARIABLE.fullmatch(variable) is None
        or not 1 <= len(commits) <= _MAX_COMMITS
        or any(_COMMIT_ID.fullmatch(commit) is None for commit in commits)
        or start.control_after != (";",)
        or start.control_before not in {("&&",), (";",)}
    ):
        return None
    expected_query = ("do", "git", "merge-base", "--is-ancestor", f"${variable}", "HEAD", "2>/dev/null")
    if query.tokens != expected_query or query.control_before != (";",) or query.control_after != ("&&",):
        return None
    if query.effective_cwd is None or not _same_path(query.effective_cwd, workspace_root):
        return None
    if trusted_git_binary_for_cwd(workspace_root) is None:
        return None
    if yes.tokens != ("echo", f"${variable} YES") or yes.control_before != ("&&",) or yes.control_after != ("||",):
        return None
    if no.tokens != ("echo", f"${variable} NO") or no.control_before != ("||",) or no.control_after != (";",):
        return None
    if end.tokens != ("done",) or end.control_before != (";",) or end.control_after not in {(), (";",)}:
        return None
    return index + 5


def _safe_status_suffix(segments: tuple[ShellExecutionSegment, ...], *, workspace_root: Path) -> bool:
    index = 0
    if index < len(segments) and _is_static_echo(segments[index], before=";", after=";"):
        index += 1
    if index < len(segments) and _is_git_log(segments[index], workspace_root=workspace_root):
        index += 1
        if index < len(segments) and _is_static_echo(segments[index], before=";", after=";"):
            index += 1
        if index + 2 != len(segments):
            return False
        fallback = segments[index + 1]
        return bool(
            _is_numeric_file_cat(segments[index], workspace_root=workspace_root)
            and len(fallback.tokens) == 2
            and fallback.tokens[0] == "echo"
            and "$" not in fallback.tokens[1]
            and "`" not in fallback.tokens[1]
            and fallback.control_before == ("||",)
            and not fallback.control_after
        )
    if index + 5 != len(segments):
        return False
    head, condition, success, fallback, end = segments[index : index + 5]
    if head.tokens != ("echo", "HEAD: $(git log -1 --oneline)") or head.control_before != (";",):
        return False
    if not _git_log_is_execution_free(workspace_root):
        return False
    if len(condition.tokens) != 5 or condition.tokens[:3] != ("if", "[", "-f") or condition.tokens[4] != "]":
        return False
    target = condition.tokens[3]
    if condition.control_before != (";",) or condition.control_after != (";",):
        return False
    if success.tokens != ("then", "echo", f"LOCK: $(cat {target})") or success.control_before != (";",):
        return False
    if fallback.tokens[:2] != ("else", "echo") or len(fallback.tokens) != 3 or fallback.control_before != (";",):
        return False
    if "$" in fallback.tokens[2] or "`" in fallback.tokens[2]:
        return False
    if end.tokens != ("fi",) or end.control_before != (";",) or end.control_after:
        return False
    return _numeric_file_is_safe(target, workspace_root=workspace_root)


def _is_git_log(segment: ShellExecutionSegment, *, workspace_root: Path) -> bool:
    return bool(
        segment.tokens == ("git", "log", "-1", "--oneline")
        and segment.control_before == (";",)
        and segment.control_after == (";",)
        and _git_log_is_execution_free(workspace_root)
    )


def _git_log_is_execution_free(workspace_root: Path) -> bool:
    git_binary = trusted_git_binary_for_cwd(workspace_root)
    return bool(git_binary is not None and git_log_has_execution_free_config(workspace_root, git_binary=git_binary))


def _is_numeric_file_cat(segment: ShellExecutionSegment, *, workspace_root: Path) -> bool:
    return bool(
        len(segment.tokens) == 3
        and segment.tokens[0] == "cat"
        and segment.tokens[2] == "2>/dev/null"
        and segment.control_before == (";",)
        and segment.control_after == ("||",)
        and _numeric_file_is_safe(segment.tokens[1], workspace_root=workspace_root)
    )


def _numeric_file_is_safe(target_text: str, *, workspace_root: Path) -> bool:
    if not target_text or target_text.startswith(("-", "~", "/")) or "$" in target_text or "`" in target_text:
        return False
    relative_target = Path(target_text)
    if (
        len(relative_target.parts) != 2
        or relative_target.parts[1] != "pid"
        or re.fullmatch(r"\.[A-Za-z0-9_.-]{1,128}\.lock\.d", relative_target.parts[0]) is None
    ):
        return False
    target = workspace_root / relative_target
    try:
        resolved = target.resolve(strict=False)
        _ = resolved.relative_to(workspace_root)
        if not target.exists():
            return True
        if target.is_symlink() or not target.is_file():
            return False
        with target.open("rb") as handle:
            payload = handle.read(_MAX_PID_BYTES + 1)
    except (OSError, ValueError):
        return False
    return len(payload) <= _MAX_PID_BYTES and bool(re.fullmatch(rb"[0-9]+(?:\r?\n)?", payload))


def _is_static_echo(segment: ShellExecutionSegment, *, before: str, after: str) -> bool:
    return bool(
        len(segment.tokens) == 2
        and segment.tokens[0] == "echo"
        and "$" not in segment.tokens[1]
        and "`" not in segment.tokens[1]
        and segment.control_before == (before,)
        and segment.control_after == (after,)
    )


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve(strict=True) == right
    except OSError:
        return False


def _is_within(path: Path, parent: Path) -> bool:
    try:
        _ = path.relative_to(parent.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


__all__ = ["is_read_only_git_ancestry_audit"]
