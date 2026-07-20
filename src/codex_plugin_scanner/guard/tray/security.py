"""Shared secret-sanitization utility.

Single source of truth for stripping potential secrets from strings
before they enter results, logs, notifications, or diagnostics. Used
by the dashboard launcher, tray runtime, and any future module that
surfaces error messages to users or logs.

Security contract:
    - Conservative: errs toward redaction. False positives (redacting
      a benign word like "authenticated") are acceptable; false negatives
      (leaking a real token) are not.
    - Pattern-based, not semantic. Cannot catch every possible secret
      format. Layers on top of (not replaces) never-put-tokens-in-
      strings discipline at the source.
"""

from __future__ import annotations

import re

# Matches key=value or key: value patterns for common secret names.
# Case-insensitive. Captures the key name for the redaction template.
_SECRET_KV_PATTERN = re.compile(r"(?i)(token|key|secret|password|auth|bearer|credential|api[_-]?key)\s*[=:]\s*\S+")

# Matches URL fragments containing guard-token parameters.
_GUARD_TOKEN_FRAGMENT_PATTERN = re.compile(r"#guard-token=[^&\s]+")

# Matches bearer tokens in Authorization headers.
_BEARER_PATTERN = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+")


def sanitize_secret(message: str) -> str:
    """Strip potential secrets from a string.

    Redacts:
    - ``token=``, ``key=``, ``secret=``, ``password=``, ``auth=``,
      ``bearer=``, ``credential=``, ``api_key=`` patterns (and ``:`` variants)
    - ``#guard-token=...`` URL fragments
    - ``Bearer <token>`` authorization header values

    Returns the sanitized string. Never raises — if regex fails for
    any reason, returns the original message unchanged.
    """
    if not message:
        return message
    try:
        sanitized = _SECRET_KV_PATTERN.sub(r"\1=<redacted>", message)
        sanitized = _GUARD_TOKEN_FRAGMENT_PATTERN.sub("#guard-token=<redacted>", sanitized)
        sanitized = _BEARER_PATTERN.sub("Bearer <redacted>", sanitized)
        return sanitized
    except Exception:  # pragma: no cover - defensive
        return message
