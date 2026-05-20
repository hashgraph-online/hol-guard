"""Minimal JavaScript semver helpers for Guard runtime decisions."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import total_ordering

_JS_VERSION_RE = re.compile(
    r"^v?(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<prerelease>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


@total_ordering
@dataclass(frozen=True, slots=True)
class JsSemverVersion:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] | None = None

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, JsSemverVersion):
            return NotImplemented
        if (self.major, self.minor, self.patch) != (other.major, other.minor, other.patch):
            return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
        if self.prerelease is None:
            return other.prerelease is not None
        if other.prerelease is None:
            return True
        return _compare_prerelease(self.prerelease, other.prerelease) < 0


def parse_js_semver(value: str | None) -> JsSemverVersion | None:
    if not value:
        return None
    normalized = value.strip()
    matched = _JS_VERSION_RE.match(normalized)
    if matched is None:
        return None
    return JsSemverVersion(
        major=int(matched.group("major")),
        minor=int(matched.group("minor") or 0),
        patch=int(matched.group("patch") or 0),
        prerelease=tuple(matched.group("prerelease").split(".")) if matched.group("prerelease") else None,
    )


def version_matches_js_selector(version: str, selector: str) -> bool:
    parsed_version = parse_js_semver(version)
    if parsed_version is None:
        return False
    normalized_selector = selector.strip()
    if not normalized_selector or normalized_selector in {"*", "latest"}:
        return True
    return any(_matches_selector_clause(parsed_version, clause.strip()) for clause in normalized_selector.split("||"))


def highest_js_version_for_selector(versions: Sequence[str], selector: str) -> str | None:
    matching_versions: list[tuple[JsSemverVersion, str]] = []
    for version in versions:
        parsed_version = parse_js_semver(version)
        if parsed_version is None or not version_matches_js_selector(version, selector):
            continue
        matching_versions.append((parsed_version, version))
    if not matching_versions:
        return None
    matching_versions.sort()
    return matching_versions[-1][1]


def _matches_selector_clause(version: JsSemverVersion, clause: str) -> bool:
    if not clause:
        return False
    tokens = clause.replace(",", " ").split()
    if not tokens:
        return False
    if len(tokens) == 1 and not tokens[0].startswith(("^", "~", "<", ">", "=", "!")):
        exact_version = parse_js_semver(tokens[0])
        return exact_version == version if exact_version is not None else False
    return all(_matches_selector_token(version, token) for token in tokens)


def _matches_selector_token(version: JsSemverVersion, token: str) -> bool:
    if token.startswith("^"):
        return _matches_caret(version, token[1:])
    if token.startswith("~"):
        return _matches_tilde(version, token[1:])
    for operator in (">=", "<=", ">", "<", "==", "="):
        if token.startswith(operator):
            return _matches_comparator(version, operator, token[len(operator) :])
    exact_version = parse_js_semver(token)
    return exact_version == version if exact_version is not None else False


def _matches_caret(version: JsSemverVersion, lower_bound: str) -> bool:
    parsed_lower = parse_js_semver(lower_bound)
    if parsed_lower is None or version < parsed_lower:
        return False
    if parsed_lower.major > 0:
        return version < JsSemverVersion(parsed_lower.major + 1, 0, 0)
    if parsed_lower.minor > 0:
        return version < JsSemverVersion(0, parsed_lower.minor + 1, 0)
    return version < JsSemverVersion(0, 0, parsed_lower.patch + 1)


def _matches_tilde(version: JsSemverVersion, lower_bound: str) -> bool:
    parsed_lower = parse_js_semver(lower_bound)
    if parsed_lower is None or version < parsed_lower:
        return False
    normalized_lower = lower_bound.strip()
    if normalized_lower.count(".") == 0:
        return version < JsSemverVersion(parsed_lower.major + 1, 0, 0)
    return version < JsSemverVersion(parsed_lower.major, parsed_lower.minor + 1, 0)


def _matches_comparator(version: JsSemverVersion, operator: str, raw_value: str) -> bool:
    parsed_value = parse_js_semver(raw_value)
    if parsed_value is None:
        return False
    if operator == ">=":
        return version >= parsed_value
    if operator == "<=":
        return version <= parsed_value
    if operator == ">":
        return version > parsed_value
    if operator == "<":
        return version < parsed_value
    return version == parsed_value


def _compare_prerelease(left: Sequence[str], right: Sequence[str]) -> int:
    for left_token, right_token in zip(left, right, strict=False):
        if left_token == right_token:
            continue
        left_numeric = left_token.isdigit()
        right_numeric = right_token.isdigit()
        if left_numeric and right_numeric:
            return int(left_token) - int(right_token)
        if left_numeric:
            return -1
        if right_numeric:
            return 1
        return -1 if left_token < right_token else 1
    return len(left) - len(right)
