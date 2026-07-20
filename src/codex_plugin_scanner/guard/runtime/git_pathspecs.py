"""Bounded, side-effect-free Git pathspec resolution."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_GIT_PATHSPEC_TIMEOUT_SECONDS = 2.0
_GIT_PATHSPEC_OUTPUT_LIMIT = 1_048_576
_GIT_PATHSPEC_PATH_LIMIT = 10_000
_GIT_PATHSPEC_SUPPORTED_LONG_MAGIC = frozenset({"exclude", "glob", "icase", "literal", "top"})
_GIT_PATHSPEC_GLOBAL_MODES = frozenset(
    {"--glob-pathspecs", "--literal-pathspecs", "--no-literal-pathspecs", "--noglob-pathspecs"}
)


@dataclass(frozen=True, slots=True)
class GitPathspecResolution:
    """One exact tracked-file selection or a stable incomplete reason."""

    complete: bool
    reason_code: str
    repository_root: Path | None
    pathspecs: tuple[str, ...]
    resolved_paths: tuple[Path, ...]
    index_state_identity: str | None
    selection_identity: str | None


def git_pathspec_is_supported(pathspec: str) -> bool:
    if not pathspec or "\x00" in pathspec:
        return False
    if not pathspec.startswith(":"):
        return True
    if pathspec.startswith(":("):
        closing = pathspec.find(")", 2)
        if closing < 0:
            return False
        magic_text = pathspec[2:closing]
        if not magic_text:
            return False
        magic = {item.strip().lower() for item in magic_text.split(",") if item.strip()}
        if not magic or not magic.issubset(_GIT_PATHSPEC_SUPPORTED_LONG_MAGIC):
            return False
        return not ({"glob", "literal"} <= magic)
    if pathspec.startswith((":!", ":^", ":/")):
        return len(pathspec) > 2
    return pathspec == ":"


def git_literal_pathspec_path(pathspec: str) -> str | None:
    if pathspec.startswith(":(literal)"):
        literal = pathspec[len(":(literal)") :]
        return literal or None
    if pathspec.startswith(":") or any(character in pathspec for character in "*?["):
        return None
    return pathspec


def git_literal_file_selection(pathspecs: tuple[str, ...], *, cwd: Path | None) -> tuple[Path, ...] | None:
    """Return exact regular literal files without requiring a repository query."""

    if cwd is None or not pathspecs:
        return None
    try:
        effective_cwd = cwd.resolve(strict=True)
    except OSError:
        return None
    selected: list[Path] = []
    for pathspec in pathspecs:
        literal = git_literal_pathspec_path(pathspec)
        if literal is None:
            return None
        candidate = Path(literal)
        if not candidate.is_absolute():
            candidate = effective_cwd / candidate
        try:
            if candidate.is_symlink() or not candidate.is_file():
                return None
            selected.append(candidate.resolve(strict=True))
        except OSError:
            return None
    return tuple(selected)


def _git_pathspec_environment() -> dict[str, str]:
    preserved = {
        name: value
        for name, value in os.environ.items()
        if name.upper() in {"LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "TMP", "TEMP", "TMPDIR"}
    }
    preserved.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "PAGER": "cat",
        }
    )
    return preserved


def _run_git_pathspec_query(
    git_path: Path,
    args: Sequence[str],
    *,
    cwd: Path,
) -> tuple[bytes | None, str | None]:
    try:
        completed = subprocess.run(
            [str(git_path), "--no-pager", "-c", f"core.hooksPath={os.devnull}", *args],
            cwd=cwd,
            env=_git_pathspec_environment(),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=_GIT_PATHSPEC_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return None, "git_pathspec_timeout"
    except OSError:
        return None, "git_pathspec_unavailable"
    if completed.returncode != 0:
        return None, "git_pathspec_command_failed"
    if len(completed.stdout) > _GIT_PATHSPEC_OUTPUT_LIMIT:
        return None, "git_pathspec_output_limit_exceeded"
    return completed.stdout, None


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _selection_identity(
    *,
    reason_code: str,
    cwd: Path | None,
    repository_root: Path | None,
    pathspecs: Sequence[str],
    global_modes: Sequence[str],
    resolved_paths: Sequence[Path],
    index_entries: Sequence[tuple[str, str, str]],
    worktree_entries: Sequence[tuple[str, int, int, int, int, int] | tuple[str, str]],
) -> str:
    try:
        cwd_text = str(cwd.resolve(strict=False)) if cwd is not None else None
    except OSError:
        cwd_text = str(cwd) if cwd is not None else None
    payload = {
        "schema": "git-pathspec-selection-v2",
        "reason_code": reason_code,
        "cwd": cwd_text,
        "repository_root": str(repository_root) if repository_root is not None else None,
        "pathspecs": tuple(pathspecs),
        "global_modes": tuple(global_modes),
        "resolved_paths": (
            [str(path.relative_to(repository_root)) for path in resolved_paths] if repository_root is not None else []
        ),
        "index_entries": tuple(index_entries),
        "worktree_entries": tuple(worktree_entries),
    }
    canonical = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def resolve_git_pathspecs(
    pathspecs: Sequence[str],
    *,
    cwd: Path | None,
    global_modes: Sequence[str] = (),
) -> GitPathspecResolution:
    """Resolve supported pathspecs to bounded, contained tracked paths."""

    normalized_pathspecs = tuple(pathspecs)

    def incomplete(reason: str) -> GitPathspecResolution:
        return GitPathspecResolution(
            complete=False,
            reason_code=reason,
            repository_root=None,
            pathspecs=normalized_pathspecs,
            resolved_paths=(),
            index_state_identity=None,
            selection_identity=_selection_identity(
                reason_code=reason,
                cwd=cwd,
                repository_root=None,
                pathspecs=normalized_pathspecs,
                global_modes=global_modes,
                resolved_paths=(),
                index_entries=(),
                worktree_entries=(),
            ),
        )

    if cwd is None:
        return incomplete("git_pathspec_cwd_unavailable")
    if any(not git_pathspec_is_supported(pathspec) for pathspec in normalized_pathspecs):
        return incomplete("git_pathspec_unsupported_magic")
    if any(mode not in _GIT_PATHSPEC_GLOBAL_MODES for mode in global_modes):
        return incomplete("git_pathspec_unsupported_global_mode")
    git_executable = shutil.which("git")
    if git_executable is None:
        return incomplete("git_pathspec_git_unavailable")
    try:
        git_path = Path(git_executable).resolve(strict=True)
        effective_cwd = cwd.resolve(strict=True)
    except OSError:
        return incomplete("git_pathspec_cwd_unavailable")
    if not git_path.is_file() or not os.access(git_path, os.X_OK) or not effective_cwd.is_dir():
        return incomplete("git_pathspec_git_unavailable")
    root_output, reason = _run_git_pathspec_query(
        git_path,
        [*global_modes, "-C", str(effective_cwd), "rev-parse", "--show-toplevel"],
        cwd=effective_cwd,
    )
    if root_output is None:
        return incomplete(reason or "git_pathspec_repository_unavailable")
    try:
        root_text = root_output.decode("utf-8", errors="surrogateescape").strip()
        repository_root = Path(root_text).resolve(strict=True)
    except (OSError, UnicodeError):
        return incomplete("git_pathspec_repository_unavailable")
    if not repository_root.is_dir() or not _path_is_within(effective_cwd, repository_root):
        return incomplete("git_pathspec_outside_repository")
    output, reason = _run_git_pathspec_query(
        git_path,
        [
            *global_modes,
            "-C",
            str(effective_cwd),
            "ls-files",
            "-z",
            "--cached",
            "--stage",
            "--full-name",
            "--",
            *normalized_pathspecs,
        ],
        cwd=repository_root,
    )
    if output is None:
        return incomplete(reason or "git_pathspec_resolution_failed")
    raw_paths = output[:-1].split(b"\x00") if output.endswith(b"\x00") else output.split(b"\x00")
    if raw_paths == [b""]:
        raw_paths = []
    if len(raw_paths) > _GIT_PATHSPEC_PATH_LIMIT:
        return incomplete("git_pathspec_path_limit_exceeded")
    resolved_paths: list[Path] = []
    index_entries: list[tuple[str, str, str]] = []
    worktree_entries: list[tuple[str, int, int, int, int, int] | tuple[str, str]] = []
    seen_paths: set[str] = set()
    for raw_entry in raw_paths:
        metadata, separator, raw_path = raw_entry.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3 or not raw_path:
            return incomplete("git_pathspec_malformed_output")
        try:
            mode = fields[0].decode("ascii")
            object_id = fields[1].decode("ascii")
            stage = fields[2].decode("ascii")
        except UnicodeError:
            return incomplete("git_pathspec_malformed_output")
        if mode == "120000":
            return incomplete("git_pathspec_symlink_unresolved")
        if mode not in {"100644", "100755"} or stage != "0":
            return incomplete("git_pathspec_non_regular_path")
        if len(object_id) not in {40, 64} or any(character not in "0123456789abcdef" for character in object_id):
            return incomplete("git_pathspec_malformed_output")
        relative_text = raw_path.decode("utf-8", errors="surrogateescape")
        relative = PurePosixPath(relative_text)
        if relative.is_absolute() or ".." in relative.parts or relative_text in seen_paths:
            return incomplete("git_pathspec_outside_repository")
        seen_paths.add(relative_text)
        candidate = repository_root.joinpath(*relative.parts)
        try:
            if candidate.is_symlink():
                return incomplete("git_pathspec_symlink_unresolved")
            if candidate.exists() and not candidate.is_file():
                return incomplete("git_pathspec_non_regular_path")
            resolved = candidate.resolve(strict=False)
            if candidate.exists():
                path_stat = candidate.stat()
                if not stat.S_ISREG(path_stat.st_mode):
                    return incomplete("git_pathspec_non_regular_path")
                worktree_entries.append(
                    (
                        relative_text,
                        path_stat.st_dev,
                        path_stat.st_ino,
                        path_stat.st_mode,
                        path_stat.st_size,
                        path_stat.st_mtime_ns,
                    )
                )
            else:
                worktree_entries.append((relative_text, "missing"))
        except OSError:
            return incomplete("git_pathspec_path_unresolved")
        if not _path_is_within(resolved, repository_root):
            return incomplete("git_pathspec_outside_repository")
        resolved_paths.append(resolved)
        index_entries.append((relative_text, mode, object_id))
    reason_code = "git_pathspec_resolved" if resolved_paths else "git_pathspec_no_match"
    index_state_identity = hashlib.sha256(
        json.dumps(index_entries, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return GitPathspecResolution(
        complete=True,
        reason_code=reason_code,
        repository_root=repository_root,
        pathspecs=normalized_pathspecs,
        resolved_paths=tuple(resolved_paths),
        index_state_identity=index_state_identity,
        selection_identity=_selection_identity(
            reason_code=reason_code,
            cwd=effective_cwd,
            repository_root=repository_root,
            pathspecs=normalized_pathspecs,
            global_modes=global_modes,
            resolved_paths=resolved_paths,
            index_entries=index_entries,
            worktree_entries=worktree_entries,
        ),
    )


__all__ = [
    "GitPathspecResolution",
    "git_literal_file_selection",
    "git_literal_pathspec_path",
    "git_pathspec_is_supported",
    "resolve_git_pathspecs",
]
