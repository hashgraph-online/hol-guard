"""Output redaction helpers for Guard command payloads."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RedactedText:
    """Safe text plus minimal metadata about removed secrets."""

    text: str
    count: int
    classifiers: tuple[str, ...]
    original_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "count": self.count,
            "classifiers": list(self.classifiers),
            "original_sha256": self.original_sha256,
        }


_REDACTION_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "bearer-token",
        re.compile(r"(?i)\b(Bearer)\s+([A-Za-z0-9._\-]{8,})"),
        r"\1 *****",
    ),
    (
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{8,}\b"),
        "gh*****",
    ),
    (
        "aws-access-key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AKIA****************",
    ),
    (
        "npm-token",
        re.compile(r"(?im)\b(_authToken|npm[_ -]?token)\s*[:=]\s*([^\s]+)"),
        r"\1=*****",
    ),
    (
        "private-key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "-----BEGIN PRIVATE KEY-----\n*****\n-----END PRIVATE KEY-----",
    ),
    (
        "secret-env",
        re.compile(
            r"(?im)^([ \t]*)([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL)[A-Z0-9_]*)=(.+)$",
        ),
        r"\1\2=*****",
    ),
    (
        "connection-env",
        re.compile(r"(?im)^([ \t]*)([A-Z0-9_]*(?:URL|URI|DSN))=([A-Za-z][A-Za-z0-9+.-]*://.+)$"),
        r"\1\2=*****",
    ),
    (
        "connection-string",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s]+", re.IGNORECASE),
        "*****",
    ),
)


def redact_text(value: str) -> RedactedText:
    """Redact common secret-like values before Guard prints or syncs them."""

    redacted_value = value
    classifiers: list[str] = []
    total_count = 0
    for classifier, pattern, replacement in _REDACTION_PATTERNS:
        redacted_value, match_count = pattern.subn(replacement, redacted_value)
        if match_count == 0:
            continue
        classifiers.extend([classifier] * match_count)
        total_count += match_count
    return RedactedText(
        text=redacted_value,
        count=total_count,
        classifiers=tuple(dict.fromkeys(classifiers)),
        original_sha256=hashlib.sha256(value.encode("utf-8")).hexdigest(),
    )
