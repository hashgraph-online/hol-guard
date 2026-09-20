"""Redact action payloads and filesystem labels for receipts and local UI."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path, PureWindowsPath

from ..redaction import redact_text
from .secret_sensitivity import redacted_secret_path_context

_PATH_KEYS = (
    "path",
    "paths",
    "file_path",
    "file_paths",
    "filePath",
    "filePaths",
    "filepath",
    "file",
    "files",
    "filename",
    "filenames",
    "target_path",
    "target_paths",
    "targetPath",
    "targetPaths",
    "target_directory",
    "targetDirectory",
    "directory",
    "dir",
)


_SENSITIVE_RAW_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "access_token",
        "auth",
        "authorization",
        "client_secret",
        "content",
        "cookie",
        "credential",
        "credentials",
        "id_token",
        "output",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "session_token",
        "set_cookie",
        "stderr",
        "stdout",
        "token",
        "tool_response",
    }
)


_SENSITIVE_RAW_KEY_ALIASES = frozenset(key.replace("_", "") for key in _SENSITIVE_RAW_KEYS)


_PROMPT_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./-])"
    r"(?P<path>(?:"
    r"(?:~|\.{1,2})?/?(?:[A-Za-z0-9_.-]+/)*(?:\.npmrc|\.env(?:\.[A-Za-z0-9_-]+)?|id_rsa|id_ed25519)"
    r"|(?:~|\.{1,2})?/?(?:[A-Za-z0-9_.-]+/)+credentials"
    r"))"
    r"(?![A-Za-z0-9_.-])"
)


_GENERIC_POSIX_ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![:A-Za-z0-9_./-])(?P<path>/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+)(?![A-Za-z0-9_.-])"
)


_GENERIC_WINDOWS_ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./\\:-])(?P<path>[A-Za-z]:\\(?:[^\\\s'\"<>|]+\\)+[^\\\s'\"<>|]+)"
)


_GENERIC_WINDOWS_UNC_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./\\:-])(?P<path>\\\\[^\\\s'\"<>|]+\\[^\\\s'\"<>|]+(?:\\[^\\\s'\"<>|]+)+)"
)


_PROMPT_EXCERPT_LIMIT = 240


def redacted_workspace_label(workspace: Path | str | None, *, home_dir: Path | str | None = None) -> str | None:
    """Return a workspace label safe for local UI and persisted context."""

    if workspace is None:
        return None
    workspace_path = Path(workspace).expanduser()
    home_path = Path(home_dir).expanduser() if home_dir is not None else Path.home()
    resolved_workspace = _safe_resolve(workspace_path)
    resolved_home = _safe_resolve(home_path)
    if resolved_workspace.is_relative_to(resolved_home):
        relative = resolved_workspace.relative_to(resolved_home)
        return "~" if str(relative) == "." else f"~/{relative.as_posix()}"
    workspace_name = resolved_workspace.name or workspace_path.name or "workspace"
    return f".../{workspace_name}"


def _command_detail(command: str | None, *, home_dir: Path | str | None) -> str | None:
    if command is None:
        return None
    return _redact_path_mentions(redact_text(command).text, home_dir=home_dir)


def _prompt_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    redacted = redact_text(value.strip()).text
    collapsed = " ".join(redacted.split())
    if not collapsed:
        return None
    return collapsed


def _prompt_excerpt(prompt_text: str | None) -> str | None:
    if prompt_text is None:
        return None
    return prompt_text[:_PROMPT_EXCERPT_LIMIT]


def _safe_resolve(path: Path) -> Path:
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError):
        return path


def _redacted_target_path(path: str, *, home_dir: Path | str | None) -> str | None:
    stripped = path.strip()
    if not stripped:
        return None
    if stripped == "~" or stripped.startswith("~/"):
        return redact_text(stripped).text
    if stripped.startswith("~"):
        secret_context = redacted_secret_path_context(stripped)
        if secret_context is not None:
            return secret_context
        target_name = Path(stripped).name or "path"
        return f".../{target_name}"
    windows_path = PureWindowsPath(stripped)
    if windows_path.is_absolute():
        secret_context = redacted_secret_path_context(stripped)
        if secret_context is not None:
            return secret_context
        target_name = windows_path.name or "path"
        return f".../{target_name}"
    if _is_absolute_target_path(stripped):
        redacted_path = redacted_workspace_label(stripped, home_dir=home_dir)
        if redacted_path is None:
            return None
        if redacted_path.startswith(".../"):
            secret_context = redacted_secret_path_context(stripped)
            if secret_context is not None:
                return secret_context
        return redacted_path
    return redact_text(stripped).text


def _is_absolute_target_path(path: str) -> bool:
    return Path(path).expanduser().is_absolute()


def _redacted_payload(payload: Mapping[str, object], *, home_dir: Path | str | None) -> dict[str, object]:
    return {
        str(key): _redacted_value(str(key), value, home_dir=home_dir)
        for key, value in payload.items()
        if isinstance(key, str)
    }


def _redacted_value(key: str, value: object, *, home_dir: Path | str | None) -> object:
    normalized_key = _normalized_secret_key(key)
    if normalized_key in _SENSITIVE_RAW_KEYS or normalized_key.replace("_", "") in _SENSITIVE_RAW_KEY_ALIASES:
        return "[redacted]"
    if isinstance(value, Mapping):
        return {
            str(child_key): _redacted_value(str(child_key), child_value, home_dir=home_dir)
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_redacted_value(key, item, home_dir=home_dir) for item in value]
    if isinstance(value, str):
        return _redacted_string_value(key, value, home_dir=home_dir)[:_PROMPT_EXCERPT_LIMIT]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)


def _redacted_string_value(key: str, value: str, *, home_dir: Path | str | None) -> str:
    if _is_path_like_key(key):
        redacted_path = _redacted_target_path(value, home_dir=home_dir)
        if redacted_path is not None:
            return redacted_path
    return _redact_path_mentions(redact_text(value).text, home_dir=home_dir)


def _is_path_like_key(key: str) -> bool:
    normalized_key = _normalized_secret_key(key)
    path_keys = {_normalized_secret_key(path_key) for path_key in _PATH_KEYS}
    return normalized_key in path_keys or normalized_key.replace("_", "") in {
        path_key.replace("_", "") for path_key in path_keys
    }


def _redact_path_mentions(text: str, *, home_dir: Path | str | None) -> str:
    def replace_path(match: re.Match[str]) -> str:
        return _redacted_target_path(match.group("path"), home_dir=home_dir) or match.group("path")

    redacted = _GENERIC_WINDOWS_UNC_PATH_PATTERN.sub(replace_path, text)
    redacted = _GENERIC_WINDOWS_ABSOLUTE_PATH_PATTERN.sub(replace_path, redacted)
    redacted = _GENERIC_POSIX_ABSOLUTE_PATH_PATTERN.sub(replace_path, redacted)
    return _PROMPT_PATH_PATTERN.sub(replace_path, redacted)


def _normalized_secret_key(key: str) -> str:
    normalized = key.replace("-", "_")
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", normalized)
    return normalized.lower()
