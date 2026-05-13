"""Output redaction helpers for Guard command payloads."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path


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
        "openai-token",
        re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
        "sk-*****",
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
        re.compile(r"(?im)\b(_authToken|npm[_ -]?token)\s*[:=]\s*([^\s\"',}]+)"),
        r"\1=*****",
    ),
    (
        "private-key",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "*****",
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
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"',}]+",
            re.IGNORECASE,
        ),
        "*****",
    ),
)

_SENSITIVE_TEXT_PATTERN = re.compile(r"(?i)(sk-[a-z0-9_-]+|(?:token|secret|api[_-]?key)(?:\s*[:=]\s*|\s+)[^\s,;]+)")
_POSIX_USER_PATH_PATTERN = re.compile(
    r"(?P<prefix>^|[\s\"'=({\[])(?P<root>/(?:Users|home)/[^/\s\"'`,;:)}\]]+)(?P<rest>(?:/[^\s\"'`,;:)}\]]*)?)"
)
_WINDOWS_USER_PATH_PATTERN = re.compile(
    r"(?P<prefix>^|[\s\"'=({\[])(?P<root>[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"'`,;:)}\]]+)"
    r"(?P<rest>(?:[\\/][^\s\"'`,;:)}\]]*)?)"
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


def redact_sensitive_text(value: str) -> str:
    return _SENSITIVE_TEXT_PATTERN.sub("[redacted]", value)


def redact_local_path(value: str, *, home_dir: Path | None = None) -> str:
    redacted_value = value
    if home_dir is not None:
        redacted_value = _replace_home_prefix(redacted_value, str(home_dir))
    current_home = _current_home_path()
    if current_home is not None:
        redacted_value = _replace_home_prefix(redacted_value, str(current_home))
    redacted_value = _POSIX_USER_PATH_PATTERN.sub(_replace_user_path, redacted_value)
    return _WINDOWS_USER_PATH_PATTERN.sub(_replace_user_path, redacted_value)


def _current_home_path() -> Path | None:
    try:
        return Path.home()
    except RuntimeError:
        return None


def _replace_home_prefix(value: str, home_value: str) -> str:
    home_prefix = home_value.rstrip("/\\")
    if not home_prefix or home_prefix in {"/", "\\"}:
        return value
    if value == home_prefix:
        return "~"
    separators = ("/", "\\")
    if value.startswith(home_prefix) and len(value) > len(home_prefix) and value[len(home_prefix)] in separators:
        return f"~{value[len(home_prefix) :]}"
    return value


def _replace_user_path(match: re.Match[str]) -> str:
    rest = match.group("rest")
    return f"{match.group('prefix')}~{rest}"
