"""Local-only, redacted command text for command-activity evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from ..redaction import redact_sensitive_text, redact_text
from .actions import command_text_from_tool_payload

INVOCATION_PREVIEW_MAX_CHARS = 4_096
_COMMAND_KEYS = ("command", "cmd", "shell_command", "shellCommand")
_INPUT_KEYS = ("tool_input", "toolInput", "toolArgs", "arguments")
_TOOL_NAME_KEYS = ("tool_name", "toolName", "name", "tool")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_URL_RE = re.compile(r"(?:https?|ssh|git|ftp|ftps|sftp|file)://[^\s\"']+", re.IGNORECASE)
_POSIX_ABS_PATH_RE = re.compile(r"(?<![A-Za-z0-9:])(?:\"(/[^\"]+)\"|'(/[^']+)'|(/[^\s\"']+))")
_WINDOWS_ABS_PATH_RE = re.compile(r"(?:\"[A-Za-z]:[\\/][^\"]+\"|'[A-Za-z]:[\\/][^']+'|[A-Za-z]:[\\/][^\s\"']+)")
_HOME_PATH_RE = re.compile(r"~[^\s\"']*")
_ENV_ASSIGNMENT_RE = re.compile(
    r"\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL)[A-Z0-9_]*="
    r"(?:'(?:\\'|[^'])*'|\"(?:\\\"|[^\"])*\"|\S+)",
    re.IGNORECASE,
)
_HEREDOC_RE = re.compile(
    r"(?P<op><{2}-?[ \t]*(?P<quote>['\"]?)(?P<tag>[^\s'\"\\]+)(?P=quote)[ \t]*\n)"
    r"(?P<body>.*?)(?P<end>\n[ \t]*(?P=tag)\b)",
    re.DOTALL,
)


def checked_command_from_payload(
    payload: Mapping[str, object],
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> str | None:
    """Return the command string Guard actually checked, when one is present."""

    del cwd, home_dir
    tool_name = _first_string(payload, _TOOL_NAME_KEYS)
    tool_input = _first_mapping(payload, _INPUT_KEYS)
    if not tool_input:
        call_name, call_input = _tool_call_input(payload.get("toolCalls"), expected_tool_name=tool_name)
        tool_name = tool_name or call_name
        tool_input = call_input
    rendered = command_text_from_tool_payload(tool_name, tool_input)
    if rendered:
        return rendered
    for key in _COMMAND_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def build_invocation_preview(command_text: str | None, *, home_dir: Path | str | None = None) -> str | None:
    """Return a bounded local display string with secrets and private paths removed."""

    if not isinstance(command_text, str):
        return None
    stripped = command_text.strip()
    if not stripped:
        return None
    redacted = _scrub_residual_private_text(_redact_home_prefix(stripped, home_dir=home_dir))
    preview = redact_sensitive_text(redact_text(redacted).text).strip()
    if not preview:
        return None
    if len(preview) > INVOCATION_PREVIEW_MAX_CHARS:
        preview = f"{preview[: INVOCATION_PREVIEW_MAX_CHARS - 1]}…"
    return preview


def build_invocation_preview_from_payload(
    payload: Mapping[str, object],
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> str | None:
    return build_invocation_preview(
        checked_command_from_payload(payload, cwd=cwd, home_dir=home_dir),
        home_dir=home_dir,
    )


def _first_string(payload: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _first_mapping(payload: Mapping[str, object], keys: tuple[str, ...]) -> Mapping[str, object] | None:
    for key in keys:
        parsed = _as_mapping(payload.get(key))
        if parsed is not None:
            return parsed
    return None


def _tool_call_input(
    value: object,
    *,
    expected_tool_name: str | None,
) -> tuple[str | None, Mapping[str, object] | None]:
    if not isinstance(value, list):
        return None, None
    fallback: tuple[str, Mapping[str, object] | None] | None = None
    for item in value:
        if not isinstance(item, Mapping):
            continue
        tool_name = item.get("name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            continue
        tool_input = _as_mapping(item.get("args"))
        if fallback is None:
            fallback = (tool_name.strip(), tool_input)
        if expected_tool_name is None or tool_name == expected_tool_name:
            return tool_name.strip(), tool_input
    if fallback is not None:
        return fallback
    return None, None


def _as_mapping(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, Mapping) else None


def _redact_home_prefix(value: str, *, home_dir: Path | str | None) -> str:
    if home_dir is None:
        return value
    home = str(home_dir).rstrip("/\\")
    if not home:
        return value
    return value.replace(home, "~")


def _scrub_residual_private_text(value: str) -> str:
    scrubbed = _HEREDOC_RE.sub(r"\g<op>…\g<end>", value)
    scrubbed = _ENV_ASSIGNMENT_RE.sub("[redacted]", scrubbed)
    scrubbed = _URL_RE.sub("[redacted]", scrubbed)
    scrubbed = _POSIX_ABS_PATH_RE.sub("[redacted]", scrubbed)
    scrubbed = _WINDOWS_ABS_PATH_RE.sub("[redacted]", scrubbed)
    scrubbed = _HOME_PATH_RE.sub("[redacted]", scrubbed)
    scrubbed = _EMAIL_RE.sub("[redacted]", scrubbed)
    return redact_text(scrubbed).text


__all__ = (
    "INVOCATION_PREVIEW_MAX_CHARS",
    "build_invocation_preview",
    "build_invocation_preview_from_payload",
    "checked_command_from_payload",
)
