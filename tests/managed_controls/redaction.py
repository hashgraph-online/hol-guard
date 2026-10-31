"""Recursive redaction for Managed Controls diagnostics."""

from __future__ import annotations

import re
from collections.abc import Mapping

_SENSITIVE_KEYS = frozenset({"command", "raw_command", "path", "source_path", "secret", "token", "proof", "nonce"})
_SENSITIVE_KEY_PATTERN = re.compile(
    rf"(?:^|[_-])(?:{'|'.join(sorted(_SENSITIVE_KEYS))})(?:$|[_-])",
    re.IGNORECASE,
)


def _is_sensitive_key(value: object) -> bool:
    return _SENSITIVE_KEY_PATTERN.search(str(value)) is not None


def redact_managed_controls(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): ("[REDACTED]" if _is_sensitive_key(key) else redact_managed_controls(child))
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [redact_managed_controls(child) for child in value]
    return value
