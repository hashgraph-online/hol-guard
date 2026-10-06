"""Conservative redaction for user-facing Guard errors and diagnostics.

This module is platform-neutral and safe for the CLI, browser dashboard,
Desktop bootstrap, notifications, and support diagnostics. It does not own any
native UI lifecycle.
"""

from __future__ import annotations

import logging
import re
from contextlib import suppress

_LOGGER = logging.getLogger(__name__)

_SECRET_KV_PATTERN = re.compile(
    r"(?i)\b(token|key|secret|password|auth|credential|api[_-]?key)\s*[=:]\s*"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^,;&\r\n]+)"
)
_GUARD_TOKEN_FRAGMENT_PATTERN = re.compile(r"#guard-token=[^&\s\"'<>]+")
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")


def sanitize_secret(message: str) -> str:
    """Strip likely secrets from a user-facing string.

    This intentionally favors false-positive redaction over leaking a token,
    credential, password, API key, or authenticated dashboard fragment.
    If sanitization cannot finish, hide the complete diagnostic.
    """

    if not message:
        return message
    try:
        sanitized = _SECRET_KV_PATTERN.sub(r"\1=<redacted>", message)
        sanitized = _GUARD_TOKEN_FRAGMENT_PATTERN.sub("#guard-token=<redacted>", sanitized)
        return _BEARER_PATTERN.sub("Bearer <redacted>", sanitized)
    except Exception:
        # A failing log handler must not prevent the safe fallback.
        with suppress(Exception):
            # Emit only a constant event, never diagnostic or exception details.
            _LOGGER.warning("secret_redaction_failed")
        return "<redacted>"
