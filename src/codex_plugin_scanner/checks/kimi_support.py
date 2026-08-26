"""Shared strict helpers for Kimi plugin checks."""

from __future__ import annotations

import re
from typing import cast
from urllib.parse import urlparse

from ..ecosystems.types import NormalizedPackage

NPM_PACKAGE_RE = re.compile(r"^@[a-z0-9._-]+/[a-z0-9._-]+(?:@[^/\\]+)?$", re.IGNORECASE)


def manifest_label(package: NormalizedPackage) -> str:
    return package.manifest_path.name if package.manifest_path else "kimi.plugin.json"


def object_sequence(value: object) -> list[object] | None:
    if not isinstance(value, list):
        return None
    return cast(list[object], value)


def looks_like_path(value: str) -> bool:
    if re.match(r"^[A-Za-z]:", value):
        return True
    if NPM_PACKAGE_RE.fullmatch(value) or urlparse(value).scheme in {"http", "https"}:
        return False
    return value.startswith((".", "/", "\\", "~")) or "/" in value or "\\" in value
