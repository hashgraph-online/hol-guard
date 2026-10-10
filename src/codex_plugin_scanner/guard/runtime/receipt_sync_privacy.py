"""Cloud-safe command text for receipts sent through Guard Cloud sync."""

from __future__ import annotations

from ..redaction import redact_sensitive_text
from .local_request_snapshots import _cloud_scrub_text

_RECEIPT_ENVELOPE_COMMAND_KEYS = ("command", "redacted_command")


def cloud_sync_sanitize_text(value: str, *, fallback: str) -> str:
    redacted = redact_sensitive_text(value).strip()
    if not redacted:
        return fallback
    if _looks_like_source_excerpt(redacted):
        return fallback
    if len(redacted) > 320:
        return f"{redacted[:317]}..."
    return redacted


def _looks_like_source_excerpt(value: str) -> bool:
    lowered = value.lower()
    suspicious_tokens = (
        "function ",
        "def ",
        "class ",
        "import ",
        "from ",
        " => ",
        "console.log(",
        "<script",
        "#!/bin/",
    )
    has_structured_code_shape = "\n" in value and ("{" in value or "}" in value or ";" in value)
    return has_structured_code_shape or any(token in lowered for token in suspicious_tokens)


def cloud_sync_command_display_part(value: str) -> str:
    # Same CLI credential-argument scrub as Cloud review events.
    return " ".join(cloud_sync_sanitize_text(_cloud_scrub_text(value), fallback="").split())


def cloud_sync_scrub_envelope_commands(envelope: dict[str, object], *, redaction_level: str) -> dict[str, object]:
    # Stored receipt envelopes keep locally redacted command text, which can still
    # carry CLI credential flags. Re-scrub at the sync boundary, and drop the text
    # when the current redaction level withholds commands.
    safe = dict(envelope)
    for key in _RECEIPT_ENVELOPE_COMMAND_KEYS:
        value = safe.get(key)
        if not isinstance(value, str):
            continue
        if redaction_level == "full":
            safe.pop(key)
        else:
            safe[key] = cloud_sync_command_display_part(value)
    return safe
