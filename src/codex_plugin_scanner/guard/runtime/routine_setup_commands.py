"""Strict benign proofs for routine agent setup commands."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from .git_execution_safety import (
    git_binary_path_is_trusted,
    git_worktree_add_has_execution_free_config,
    trusted_git_binary_for_cwd,
)

_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_REF = re.compile(r"(?:origin/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}|[0-9a-f]{7,40})")
_RG_FLAGS = frozenset({"-F", "-i", "-n", "--fixed-strings", "--ignore-case", "--line-number"})
_PROBE_TIMEOUT_SECONDS = 1.0


def is_safe_git_worktree_add(command_text: str, *, cwd: Path | None, home_dir: Path) -> bool:
    """Accept one new branch or detached worktree under a bounded developer root."""

    tokens = _literal_tokens(command_text)
    if tokens is None or cwd is None:
        return False
    branch: str | None
    if len(tokens) == 7 and tokens[:4] == ["git", "worktree", "add", "-b"]:
        branch, destination_text, ref = tokens[4:]
        if not _safe_git_name(branch, _BRANCH):
            return False
    elif len(tokens) == 6 and tokens[:4] == ["git", "worktree", "add", "--detach"]:
        branch = None
        destination_text, ref = tokens[4:]
        if re.fullmatch(r"[0-9a-f]{40}", ref) is None:
            return False
    else:
        return False
    if destination_text.startswith("-") or not _safe_git_name(ref, _REF):
        return False
    try:
        execution_cwd = cwd.resolve(strict=True)
        destination = _absolute_destination(destination_text, cwd=execution_cwd, home_dir=home_dir)
    except (OSError, RuntimeError):
        return False
    if destination is None or destination.exists() or destination.is_symlink():
        return False
    if not _safe_worktree_parent(destination, home_dir=home_dir):
        return False
    git_binary = trusted_git_binary_for_cwd(execution_cwd)
    if git_binary is None or not git_worktree_add_has_execution_free_config(
        execution_cwd,
        git_binary=git_binary,
        ref=ref,
    ):
        return False
    if not _git_ref_exists(git_binary, execution_cwd, ref):
        return False
    return branch is None or not _git_branch_exists(git_binary, execution_cwd, branch)


def is_safe_codex_memory_registry_search(command_text: str, *, cwd: Path | None, home_dir: Path) -> bool:
    """Accept a single bounded ripgrep search of Codex's memory registry."""

    tokens = _literal_tokens(command_text)
    if tokens is None or len(tokens) < 3 or tokens[0] != "rg" or cwd is None:
        return False
    operands: list[str] = []
    after_options = False
    for token in tokens[1:]:
        if not after_options and token == "--":
            after_options = True
            continue
        if not after_options and token.startswith("-"):
            if token not in _RG_FLAGS:
                return False
            continue
        operands.append(token)
    if len(operands) != 2 or any(character in operands[0] for character in ("\0", "\r", "\n")):
        return False
    target = _expand_path(operands[1], cwd=cwd, home_dir=home_dir)
    expected = home_dir / ".codex" / "memories" / "MEMORY.md"
    try:
        if (
            target.absolute() != expected.absolute()
            or _path_has_symlink_below_home(expected, home_dir=home_dir)
            or target.is_symlink()
            or not target.is_file()
            or target.stat().st_size > 4 * 1024 * 1024
        ):
            return False
        rg_path = _trusted_path_command("rg", cwd=cwd)
    except (OSError, RuntimeError):
        return False
    return rg_path is not None and not os.environ.get("RIPGREP_CONFIG_PATH", "").strip()


def _path_has_symlink_below_home(path: Path, *, home_dir: Path) -> bool:
    try:
        relative_parts = path.absolute().relative_to(home_dir.absolute()).parts
    except ValueError:
        return True
    candidate = home_dir.absolute()
    for part in relative_parts:
        candidate /= part
        try:
            if candidate.is_symlink():
                return True
        except OSError:
            return True
    return False


def _literal_tokens(command_text: str) -> list[str] | None:
    if any(marker in command_text for marker in ("$(", "`", "<(", ">(", "\0", "\r", "\n")):
        return None
    try:
        tokens = shlex.split(command_text)
    except ValueError:
        return None
    if any(
        token in {"|", "||", "&&", "&", ";", "<", ">"} or re.fullmatch(r"\d*(?:>|<|>>|<<|>&|<&).+", token) is not None
        for token in tokens
    ):
        return None
    return tokens


def _safe_git_name(value: str, pattern: re.Pattern[str]) -> bool:
    return bool(
        pattern.fullmatch(value)
        and ".." not in value
        and "@{" not in value
        and "//" not in value
        and not value.endswith(("/", ".", ".lock"))
        and all(component not in {"", ".", ".."} for component in value.split("/"))
    )


def _absolute_destination(value: str, *, cwd: Path, home_dir: Path) -> Path | None:
    candidate = home_dir / value[2:] if value.startswith("~/") else Path(value)
    if not candidate.is_absolute():
        candidate = cwd / candidate
    return candidate.absolute()


def _safe_worktree_parent(destination: Path, *, home_dir: Path) -> bool:
    try:
        parent = destination.parent
        resolved_parent = parent.resolve(strict=True)
        allowed_roots = (Path("/tmp").resolve(strict=True), (home_dir / "CascadeProjects").resolve(strict=True))
    except (OSError, RuntimeError):
        return False
    if not resolved_parent.is_dir():
        return False
    return any(resolved_parent == root or root in resolved_parent.parents for root in allowed_roots)


def _git_ref_exists(git_binary: Path, cwd: Path, ref: str) -> bool:
    try:
        result = subprocess.run(
            [str(git_binary), "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and bool(re.fullmatch(r"[0-9a-f]{40}\n?", result.stdout))


def _git_branch_exists(git_binary: Path, cwd: Path, branch: str) -> bool:
    try:
        result = subprocess.run(
            [str(git_binary), "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return True
    return result.returncode != 1 or bool(result.stdout or result.stderr)


def _expand_path(value: str, *, cwd: Path, home_dir: Path) -> Path:
    if value.startswith("~/"):
        return home_dir / value[2:]
    path = Path(value)
    return path if path.is_absolute() else cwd / path


def _trusted_path_command(command: str, *, cwd: Path) -> Path | None:
    path_entries: list[str] = []
    for entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
        candidate = Path(entry or ".").expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        path_entries.append(str(candidate))
    path = shutil.which(command, path=os.pathsep.join(path_entries))
    if path is None:
        return None
    try:
        resolved = Path(path).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if git_binary_path_is_trusted(resolved, cwd=cwd) else None


__all__ = ("is_safe_codex_memory_registry_search", "is_safe_git_worktree_add")
