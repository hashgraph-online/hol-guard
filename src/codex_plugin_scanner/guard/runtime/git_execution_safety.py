"""Shared execution-safety checks for Git inspection commands.

The resident runtime owns every verdict (RTM-032). Each function forwards
observed facts to ``git_execution_safety`` and fails closed when the resident
cannot answer; nothing here evaluates Git configuration, binaries, or hooks.
"""

from __future__ import annotations

from pathlib import Path


def _ask(
    check: str,
    *,
    cwd: Path | None = None,
    git_binary: Path | None = None,
    git_path: Path | None = None,
    arguments: list[str] | None = None,
    branch: str | None = None,
    reference: str | None = None,
) -> tuple[bool, str | None]:
    from ..native_git_execution_safety import git_execution_safety_native

    answer = git_execution_safety_native(
        check,
        cwd=cwd,
        git_binary=git_binary,
        git_path=git_path,
        arguments=arguments,
        branch=branch,
        reference=reference,
    )
    if answer is None:
        return False, None
    return answer.allowed, answer.resolved_path


def git_binary_path_is_trusted(git_path: Path, *, cwd: Path) -> bool:
    """Reject Git executables from user-controlled or broadly writable roots."""

    return _ask("binary_trusted", cwd=cwd, git_path=git_path)[0]


def git_config_routing_environment_is_clean() -> bool:
    """Return whether Git configuration discovery follows its default routes."""

    return _ask("config_environment_clean")[0]


def trusted_git_binary_for_cwd(cwd: Path) -> Path | None:
    """Resolve Git using the execution cwd and reject user-controlled binaries."""

    allowed, resolved = _ask("resolve_binary", cwd=cwd)
    return Path(resolved) if allowed and resolved else None


def git_status_args_are_read_only(args: list[str]) -> bool:
    """Accept only status flags that cannot configure or invoke helpers."""

    return _ask("status_arguments", arguments=list(args))[0]


def git_status_has_execution_free_config(cwd: Path, *, git_binary: Path | None = None) -> bool:
    """Verify status cannot run configured helpers."""

    return _ask("status_config", cwd=cwd, git_binary=git_binary)[0]


def git_object_query_has_no_lazy_fetch(cwd: Path, *, git_binary: Path | None = None) -> bool:
    """Verify an object query cannot lazily fetch or run helpers."""

    return _ask("object_query", cwd=cwd, git_binary=git_binary)[0]


def git_fetch_origin_has_execution_free_config(cwd: Path, *, git_binary: Path | None = None) -> bool:
    """Verify a configured-origin fetch cannot redirect execution."""

    return _ask("fetch_origin", cwd=cwd, git_binary=git_binary)[0]


def git_push_origin_has_execution_free_config(cwd: Path, *, branch: str, git_binary: Path | None = None) -> bool:
    """Verify a configured-origin push cannot redirect execution or change branches."""

    return _ask("push_origin", cwd=cwd, git_binary=git_binary, branch=branch)[0]


def git_worktree_add_has_execution_free_config(cwd: Path, *, git_binary: Path | None = None, ref: str = "HEAD") -> bool:
    """Reject worktree creation when checkout can invoke configured code."""

    return _ask("worktree_add", cwd=cwd, git_binary=git_binary, reference=ref)[0]


__all__ = (
    "git_binary_path_is_trusted",
    "git_config_routing_environment_is_clean",
    "git_fetch_origin_has_execution_free_config",
    "git_object_query_has_no_lazy_fetch",
    "git_push_origin_has_execution_free_config",
    "git_status_args_are_read_only",
    "git_status_has_execution_free_config",
    "git_worktree_add_has_execution_free_config",
    "trusted_git_binary_for_cwd",
)
