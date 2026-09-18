"""Shared exact-version projection for package lockfile selectors."""

from __future__ import annotations

from .npm_source_spec import parse_npm_source_spec


def exact_lockfile_version(value: str | None) -> str | None:
    normalized = value.strip() if isinstance(value, str) else ""
    if not normalized or parse_npm_source_spec(normalized) is not None:
        return None
    if normalized.startswith(("^", "~", "<", ">", "!", "*")):
        return None
    if any(token in normalized for token in ("||", " - ", ",")):
        return None
    return normalized


def direct_lockfile_version(value: str) -> str | None:
    normalized = value.split("(", 1)[0].strip()
    if normalized.startswith("npm:"):
        normalized = normalized.partition("npm:")[2]
    if "@" in normalized and not normalized.startswith("@"):
        candidate = normalized.rsplit("@", 1)[-1]
        if exact_lockfile_version(candidate) is not None:
            return candidate
    if exact_lockfile_version(normalized) is not None:
        return normalized
    return None
