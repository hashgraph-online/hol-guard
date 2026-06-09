"""Output redaction helpers for Guard command payloads."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class RedactedText:
    """Safe text plus minimal metadata about removed secrets.

    ``original_sha256`` is a legacy payload key kept for response shape
    compatibility. It is intentionally empty so secret-bearing input never
    becomes a hash oracle.
    """

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
        "python-index-token",
        re.compile(r"(?im)\b(index-url|extra-index-url)\s*[:=]\s*(https?://[^@\s]+@[^\s]+)"),
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
    (
        "remote-pairing-code",
        re.compile(r"\bHLG-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{6}\b"),
        "HLG-******",
    ),
)

_SENSITIVE_INLINE_PREFIX_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r'(?i)"?sync_state\.credentials"?\s*[:=]\s*',
    ),
    re.compile(
        r'(?i)"?(?:access[_-]?token|refresh[_-]?token|authorization[_-]?code|user[_-]?code|'
        r'dpop[_-]?private[_-]?key(?:[_-]?(?:pem|ref))?)"?\s*[:=]\s*',
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
        original_sha256="",
    )


def redact_sensitive_text(value: str) -> str:
    redacted = value
    for pattern in _SENSITIVE_INLINE_PREFIX_PATTERNS:
        redacted = _redact_inline_secret_assignments(redacted, pattern)
    return _SENSITIVE_TEXT_PATTERN.sub("[redacted]", redacted)


def _redact_inline_secret_assignments(value: str, pattern: re.Pattern[str]) -> str:
    redacted: list[str] = []
    search_start = 0
    while True:
        match = pattern.search(value, search_start)
        if match is None:
            redacted.append(value[search_start:])
            return "".join(redacted)
        redacted.append(value[search_start : match.start()])
        redacted.append("[redacted]")
        search_start = _consume_inline_secret_value(value, match.end())


def _consume_inline_secret_value(value: str, start: int) -> int:
    if start >= len(value):
        return start

    opening = value[start]
    if opening in {'"', "'"}:
        return _consume_quoted_secret_value(value, start, opening)
    if opening in {"{", "["}:
        return _consume_balanced_secret_value(value, start)

    end = start
    while end < len(value) and value[end] not in ", \t\r\n;}]":
        end += 1
    return end


def _consume_quoted_secret_value(value: str, start: int, quote: str) -> int:
    index = start + 1
    while index < len(value):
        character = value[index]
        if character == "\\":
            index += 2
            continue
        index += 1
        if character == quote:
            return index
    return len(value)


def _consume_balanced_secret_value(value: str, start: int) -> int:
    closing_for_opening = {"{": "}", "[": "]"}
    stack = [closing_for_opening[value[start]]]
    index = start + 1
    active_quote: str | None = None

    while index < len(value):
        character = value[index]
        if active_quote is not None:
            if character == "\\":
                index += 2
                continue
            index += 1
            if character == active_quote:
                active_quote = None
            continue

        if character in {'"', "'"}:
            active_quote = character
            index += 1
            continue
        if character in closing_for_opening:
            stack.append(closing_for_opening[character])
            index += 1
            continue

        index += 1
        if character == stack[-1]:
            stack.pop()
            if not stack:
                return index

    return len(value)


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
