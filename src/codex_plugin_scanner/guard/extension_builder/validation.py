"""Publishable identifiers and metadata, never shell syntax or credentials."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from .errors import BuilderError

SLUG_PATTERN = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"
TOKEN_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.+-]*"
COMMAND_TOKEN_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.:+-]*"
OPTION_PATTERN = r"--?[A-Za-z0-9][A-Za-z0-9_-]*"
TOOL_PATTERN = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
SHA_PATTERN = r"[a-f0-9]{64}"
RISKS = ("execution", "destructive_shell", "network_egress", "local_secret_read")
LAUNCHERS = ("npx", "uvx", "bunx", "pnpm", "npm", "yarn", "pipx")
_RESERVED = frozenset(
    {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
)


def text(value: object, *, maximum: int = 128, empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or value != value.strip()
        or (not value and not empty)
        or any(
            ord(char) < 32
            or 127 <= ord(char) <= 159
            or 0xD800 <= ord(char) <= 0xDFFF
            or char in "\u2028\u2029\u202e\u202d\u2066\u2067\u2068\u2069"
            for char in value
        )
    ):
        raise BuilderError("invalid_text", "Metadata must be bounded, single-line, printable text.")
    return value


def token(value: object, *, pattern: str = TOKEN_PATTERN, maximum: int = 64) -> str:
    result = text(value, maximum=maximum)
    if re.fullmatch(pattern, result) is None:
        raise BuilderError("invalid_identifier", "An authoring identifier has unsupported characters.")
    return result


def slug(value: object) -> str:
    result = token(value, pattern=SLUG_PATTERN, maximum=40)
    if result in _RESERVED:
        raise BuilderError("invalid_slug", "This slug is reserved on supported filesystems.")
    return result


def https_reference(value: object, *, empty: bool = False) -> str:
    result = text(value, maximum=512, empty=empty)
    if not result and empty:
        return result
    try:
        parsed = urlsplit(result)
        valid = (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and parsed.port in {None, 443}
            and all(ord(char) < 128 for char in result)
            and not any(char in result for char in '\\ "<>{}`')
        )
    except ValueError:
        valid = False
    if not valid:
        raise BuilderError("invalid_reference", "References must be HTTPS URLs without credentials or query strings.")
    return result


def package_identity(value: object, launcher: str) -> str:
    result = text(value, maximum=256)
    pattern = r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*"
    if launcher in {"uvx", "pipx"}:
        pattern = r"[A-Za-z0-9][A-Za-z0-9._-]*"
    if re.fullmatch(pattern, result) is None or result.endswith((".", "-", "_")):
        raise BuilderError("invalid_package", "Use an unversioned registry package name, not a URL or launch command.")
    return result


def normalized_tool_name(value: str) -> str:
    return "-".join(part for part in re.sub(r"[^a-z0-9]", "-", value.lower()).split("-") if part)
