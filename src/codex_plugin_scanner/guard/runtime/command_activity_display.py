"""Local-only, redacted command text for command-activity evidence."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path

from ..redaction import redact_sensitive_text, redact_text
from .actions import _command_detail, command_text_from_tool_payload
from .secret_file_requests import extract_sensitive_tool_action_request

INVOCATION_PREVIEW_MAX_CHARS = 4_096
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_ENV_ASSIGNMENT_RE = re.compile(
    r"\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL)[A-Z0-9_]*=\S+",
    re.IGNORECASE,
)
_HEREDOC_RE = re.compile(
    r"(?P<op><{2}-?[\"']?(?P<tag>\w+)[\"']?[ \t]*\n)(?P<body>.*?)(?P<end>\n[ \t]*(?P=tag)\b)",
    re.DOTALL,
)


def checked_command_from_payload(
    payload: Mapping[str, object],
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> str | None:
    """Return the command string Guard actually checked, when one is present."""

    arguments = payload.get("tool_input", payload.get("toolInput", payload.get("arguments")))
    tool_name = payload.get("tool_name", payload.get("toolName"))
    rendered = command_text_from_tool_payload(tool_name, arguments)
    if rendered:
        return rendered
    for key in ("command", "cmd"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    request = extract_sensitive_tool_action_request(
        tool_name,
        arguments,
        cwd=cwd,
        home_dir=home_dir,
    )
    if request is None:
        return None
    command_text = request.raw_command_text or request.command_text
    if isinstance(command_text, str) and command_text.strip():
        return command_text.strip()
    return None


def build_invocation_preview(command_text: str | None, *, home_dir: Path | str | None = None) -> str | None:
    """Return a bounded local display string with secrets and private paths removed."""

    if not isinstance(command_text, str):
        return None
    stripped = command_text.strip()
    if not stripped:
        return None
    redacted = _command_detail(redact_sensitive_text(redact_text(stripped).text), home_dir=home_dir)
    if redacted is None:
        return None
    preview = _scrub_residual_private_text(redacted).strip()
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


def _scrub_residual_private_text(value: str) -> str:
    scrubbed = _HEREDOC_RE.sub(r"\g<op>…\g<end>", value)
    scrubbed = _ENV_ASSIGNMENT_RE.sub("[redacted]", scrubbed)
    scrubbed = _URL_RE.sub("[redacted]", scrubbed)
    scrubbed = _EMAIL_RE.sub("[redacted]", scrubbed)
    return redact_text(scrubbed).text


__all__ = (
    "INVOCATION_PREVIEW_MAX_CHARS",
    "build_invocation_preview",
    "build_invocation_preview_from_payload",
    "checked_command_from_payload",
)
