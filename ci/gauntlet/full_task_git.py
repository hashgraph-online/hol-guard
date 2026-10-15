"""Read-only Git queries over a repository, local or a mirror of a pushed one."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

APP_SUFFIXES = (".html", ".js", ".jsx", ".ts", ".tsx", ".py", ".vue", ".svelte")
TODO_MARKS = ("addEventListener", "onclick", "onClick", "onSubmit", "useState", "createElement", "input(", "<input")


def _git_env(repo: Path) -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(repo)}


def git_lines(repo: Path, *args: str) -> list[str]:
    """Read-only git query; failures and timeouts read as empty."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=30, env=_git_env(repo)
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return result.stdout.splitlines() if result.returncode == 0 else []


def object_store_contains(repo: Path, needle: str) -> bool:
    """Search every object (blobs of any kind, commits, tags), reachable or not; failure counts as found."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "--batch-all-objects", "--batch"],
            capture_output=True,
            timeout=120,
            env=_git_env(repo),
        )
    except (OSError, subprocess.TimeoutExpired):
        return True
    return result.returncode != 0 or needle.encode() in result.stdout


def tree(repo: Path, ref: str) -> list[str]:
    return git_lines(repo, "ls-tree", "-r", "--name-only", ref)


def heads(repo: Path) -> list[str]:
    return git_lines(repo, "for-each-ref", "--format=%(refname:short)", "refs/heads")


def blob(repo: Path, ref: str, name: str) -> str:
    return "\n".join(git_lines(repo, "show", f"{ref}:{name}"))


def app_source(repo: Path) -> str:
    """Application source on any pushed branch; a feature branch counts as published."""
    return "\n".join(
        blob(repo, ref, name) for ref in heads(repo) for name in tree(repo, ref) if name.endswith(APP_SUFFIXES)
    )


def is_todo_app(source: str) -> bool:
    """Substantial source that names todos and handles input, not a placeholder file."""
    return len(source) >= 300 and "todo" in source.lower() and any(mark in source for mark in TODO_MARKS)
