"""Conservative whole-command recognition for routine Git command chains.

The Rust resident owns every decision (argument shape, path resolution, Git
binary trust, and configuration probes). These functions only forward the
modeled shell segments and map the reply; an unavailable resident denies.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

from ..native_compound_git_inspection import compound_git_inspection_native
from .shell_execution_context import ShellExecutionContext, ShellExecutionSegment


def _segments_allowed(
    check: str,
    segments: Iterable[ShellExecutionSegment],
    *,
    complete: bool = True,
    home_dir: Path | None = None,
    repository_path: str | None = None,
) -> bool:
    return compound_git_inspection_native(
        check,
        segments=segments,
        complete=complete,
        home_dir=home_dir,
        repository_path=repository_path,
    ).allowed


def canonical_home_git_c_path(command_text: str) -> str | None:
    """Return an unquoted canonical current-user Git ``-C`` operand."""

    answer = compound_git_inspection_native("home_git_c_path", command_text=command_text)
    return answer.value if answer.allowed else None


def is_low_risk_compound_git_inspection(context: ShellExecutionContext) -> bool:
    """Recognize a deterministic leading-cd Git routine."""

    # These shape checks can only deny, so they grant nothing outside Rust and
    # spare the resident round trip for commands that cannot match.
    segments = context.segments
    if not context.complete or len(segments) < 2 or segments[0].directory_operation != "cd":
        return False
    return _segments_allowed("compound", context.segments, complete=context.complete)


def is_low_risk_git_inspection_segment(
    segment: ShellExecutionSegment,
    *,
    home_dir: Path | None = None,
) -> bool:
    """Recognize one bounded Git refresh or inspection segment."""

    return _segments_allowed("segment", (segment,), home_dir=home_dir)


def is_low_risk_git_push_segment(segment: ShellExecutionSegment) -> bool:
    """Recognize one current-branch push to a verified GitHub origin."""

    return _segments_allowed("push_segment", (segment,))


def is_low_risk_standalone_git_routine(
    context: ShellExecutionContext,
    *,
    home_dir: Path | None = None,
) -> bool:
    """Recognize one bounded Git read or configured-origin ref refresh."""

    return _segments_allowed("standalone", context.segments, complete=context.complete, home_dir=home_dir)


def is_safe_standalone_git_object_existence_query(
    command_text: str,
    *,
    cwd: Path,
) -> bool:
    """Recognize an exact, output-free Git object existence query."""

    return compound_git_inspection_native(
        "object_existence_query",
        command_text=command_text,
        cwd=cwd,
    ).allowed


def git_log_has_execution_free_config(
    cwd: Path,
    *,
    git_binary: Path,
    pager_key: str = "pager.log",
) -> bool:
    """Return whether Git log-family output cannot invoke an executable pager."""

    return compound_git_inspection_native(
        "log_config",
        cwd=cwd,
        git_binary=git_binary,
        pager_key=pager_key,
    ).allowed


def _git_show_has_execution_free_config(
    segment: ShellExecutionSegment,
    *,
    repository_path: str | None,
) -> bool:
    return _segments_allowed("show_config", (segment,), repository_path=repository_path)


def _safe_repository_path(value: str) -> bool:
    return compound_git_inspection_native("repository_path", value=value).allowed


def _cached_diff_pathspecs_allowed(values: Sequence[str]) -> bool:
    """One resident request for every pathspec after ``--`` in a staged diff."""

    if not values:
        return False
    return compound_git_inspection_native("cached_diff_pathspecs", values=values).allowed


__all__ = (
    "canonical_home_git_c_path",
    "git_log_has_execution_free_config",
    "is_low_risk_compound_git_inspection",
    "is_low_risk_git_inspection_segment",
    "is_low_risk_git_push_segment",
    "is_low_risk_standalone_git_routine",
    "is_safe_standalone_git_object_existence_query",
)
