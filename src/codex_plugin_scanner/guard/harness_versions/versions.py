"""Exact harness version parsing.

Coverage compares exact versions only. A prerelease is never coerced to its
stable release and a build identifier stays part of the identity, so evidence
for ``18.4.12`` says nothing about ``18.4.12-rc.1`` or ``18.4.12+abc``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_VERSION_TEXT = 64
MAX_BANNER_BYTES = 4096

_IDENTIFIER = r"[0-9A-Za-z-]+"
_VERSION_PATTERN = re.compile(
    r"^v?(?P<major>0|[1-9]\d{0,5})\.(?P<minor>0|[1-9]\d{0,5})\.(?P<patch>0|[1-9]\d{0,5})"
    rf"(?:-(?P<prerelease>{_IDENTIFIER}(?:\.{_IDENTIFIER})*))?"
    rf"(?:\+(?P<build>{_IDENTIFIER}(?:\.{_IDENTIFIER})*))?$"
)
_BANNER_TOKEN = re.compile(r"(?<!\d)v?\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")


@dataclass(frozen=True, slots=True)
class HarnessVersion:
    """One exact semantic version, including prerelease and build identity."""

    major: int
    minor: int
    patch: int
    prerelease: str | None = None
    build: str | None = None

    @property
    def canonical(self) -> str:
        text = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            text += f"-{self.prerelease}"
        if self.build:
            text += f"+{self.build}"
        return text

    @property
    def is_prerelease(self) -> bool:
        return self.prerelease is not None


def parse_version(value: object) -> HarnessVersion | None:
    """Parse one exact version string; anything else is ``None``."""

    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_VERSION_TEXT:
        return None
    match = _VERSION_PATTERN.fullmatch(text)
    if match is None:
        return None
    return HarnessVersion(
        major=int(match["major"]),
        minor=int(match["minor"]),
        patch=int(match["patch"]),
        prerelease=match["prerelease"],
        build=match["build"],
    )


# Banner prefixes a harness prints before its version. Anything else on the
# first line makes the banner malformed rather than guessable.
_BANNER_PREFIXES: dict[str, tuple[str, ...]] = {
    "omp": ("", "omp", "oh-my-pi", "@oh-my-pi/pi-coding-agent"),
}


def parse_version_banner(harness: str, banner: str) -> HarnessVersion | None:
    """Parse a ``--version`` banner using the harness's known shape only."""

    prefixes = _BANNER_PREFIXES.get(harness)
    if prefixes is None or not isinstance(banner, str):
        return None
    if len(banner.encode("utf-8", errors="replace")) > MAX_BANNER_BYTES:
        return None
    lines = [line.strip() for line in banner.splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    tokens = _BANNER_TOKEN.findall(lines[0])
    if len(tokens) != 1:
        return None
    prefix = lines[0][: lines[0].index(tokens[0])].strip().rstrip(":/").strip().lower()
    suffix = lines[0][lines[0].index(tokens[0]) + len(tokens[0]) :].strip()
    if prefix not in prefixes or suffix:
        return None
    return parse_version(tokens[0])
