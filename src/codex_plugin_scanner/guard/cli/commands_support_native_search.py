"""Validation for structured, read-only native source-search tool calls."""

from __future__ import annotations

from pathlib import Path

from ..runtime.secret_file_requests import _read_only_lookup_target_is_safe
from ..runtime.source_paths import resolve_source_candidate_path

_NATIVE_SEARCH_TOOLS = frozenset({"grep", "egrep", "fgrep", "rg"})
_EXPLICIT_COMMAND_KEYS = ("command", "cmd", "shell_command", "shellCommand")
_PATTERN_KEYS = ("pattern", "query", "search", "regex")
_TARGET_KEYS = ("path", "file_path", "filePath", "filepath", "file", "filename")
_PLURAL_TARGET_KEYS = ("paths", "files")
_GLOB_KEYS = ("glob", "include", "includes")


def native_post_tool_search_is_read_only(
    *,
    payload: dict[str, object],
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    """Return whether a structured native search payload is bounded and read-only."""
    tool_name = str(payload.get("tool_name", "")).strip().lower()
    if tool_name not in _NATIVE_SEARCH_TOOLS:
        return False
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return False
    if any(_nonempty_string(tool_input.get(key)) for key in _EXPLICIT_COMMAND_KEYS):
        return False

    present_patterns = [tool_input[key] for key in _PATTERN_KEYS if key in tool_input]
    if not present_patterns or any(not _nonempty_string(value) for value in present_patterns):
        return False
    if tool_input.get("follow") not in (None, False) or tool_input.get("hidden") not in (None, False):
        return False

    present_globs = [tool_input[key] for key in _GLOB_KEYS if key in tool_input]
    if any(not _safe_glob(value, home_dir=home_dir) for value in present_globs):
        return False

    targets = _native_search_targets(tool_input)
    if targets is None:
        return False
    if not targets:
        targets = (".",)
    return all(_native_search_target_is_safe(target, cwd=cwd, home_dir=home_dir) for target in targets)


def _native_search_targets(tool_input: dict[str, object]) -> tuple[str, ...] | None:
    targets: list[str] = []
    for key in _TARGET_KEYS:
        if key not in tool_input:
            continue
        value = tool_input[key]
        if not _nonempty_string(value):
            return None
        targets.append(str(value).strip())
    for key in _PLURAL_TARGET_KEYS:
        if key not in tool_input:
            continue
        value = tool_input[key]
        if not isinstance(value, list) or not value or any(not _nonempty_string(item) for item in value):
            return None
        targets.extend(str(item).strip() for item in value)
    return tuple(targets)


def _safe_glob(value: object, *, home_dir: Path | None) -> bool:
    return _nonempty_string(value) and _read_only_lookup_target_is_safe(
        str(value),
        allow_dirs=False,
        home_dir=home_dir,
    )


def _native_search_target_is_safe(
    target: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    if any(marker in target for marker in ("*", "?", "[", "]")):
        return False
    if not _read_only_lookup_target_is_safe(target, allow_dirs=True, home_dir=home_dir):
        return False
    candidate = resolve_source_candidate_path(target, cwd=cwd, home_dir=home_dir)
    if candidate is None:
        return False
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return False
    return (resolved.is_file() or resolved.is_dir()) and _read_only_lookup_target_is_safe(
        str(resolved), allow_dirs=True, home_dir=home_dir
    )


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


__all__ = ["native_post_tool_search_is_read_only"]
