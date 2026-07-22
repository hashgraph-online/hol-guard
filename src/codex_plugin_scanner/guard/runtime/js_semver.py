"""Minimal, fail-closed JavaScript semver helpers for Guard runtime decisions.

The range evaluator implements the npm/node-semver prerelease admission rule:
ordering a prerelease inside a comparator set is not enough to admit it.  One
comparator in the *same* ``||`` clause must itself contain a prerelease with the
candidate's exact major/minor/patch tuple.

Supported range forms are exact versions, primitive comparators, caret and
tilde ranges, partial/x ranges, and one hyphen range per clause.  Other syntax
is rejected rather than approximated as a broader range.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from functools import total_ordering

_MAX_SEMVER_LENGTH = 256
_MAX_SELECTOR_LENGTH = 1024
_MAX_SELECTOR_CLAUSES = 32
_MAX_COMPARATORS_PER_CLAUSE = 64
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_NUMERIC_COMPONENT = r"(?:0|[1-9][0-9]*)"
_IDENTIFIER = r"[0-9A-Za-z-]+"
_JS_VERSION_RE = re.compile(
    "".join(
        (
            rf"^v?(?P<major>{_NUMERIC_COMPONENT})\.(?P<minor>{_NUMERIC_COMPONENT})\.(?P<patch>{_NUMERIC_COMPONENT})",
            rf"(?:-(?P<prerelease>{_IDENTIFIER}(?:\.{_IDENTIFIER})*))?",
            rf"(?:\+(?P<build>{_IDENTIFIER}(?:\.{_IDENTIFIER})*))?$",
        )
    )
)
_HYPHEN_RANGE_RE = re.compile(r"^(?P<lower>\S+)\s+-\s+(?P<upper>\S+)$")
_COMPARATOR_RE = re.compile(r"^(?P<operator>>=|<=|>|<|=)?(?P<version>.+)$")
_WILDCARDS = frozenset({"*", "x", "X"})


@total_ordering
@dataclass(frozen=True, slots=True)
class JsSemverVersion:
    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] | None = None

    @property
    def base(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, JsSemverVersion):
            return NotImplemented
        if self.base != other.base:
            return self.base < other.base
        if self.prerelease is None:
            return False
        if other.prerelease is None:
            return True
        return _compare_prerelease(self.prerelease, other.prerelease) < 0


@dataclass(frozen=True, slots=True)
class _RangeVersion:
    major: int | None
    minor: int | None
    patch: int | None
    prerelease: tuple[str, ...] | None = None

    @property
    def complete(self) -> bool:
        return self.major is not None and self.minor is not None and self.patch is not None

    def lower_bound(self) -> JsSemverVersion | None:
        if self.major is None:
            return None
        return JsSemverVersion(
            self.major,
            self.minor or 0,
            self.patch or 0,
            self.prerelease,
        )


@dataclass(frozen=True, slots=True)
class _Comparator:
    operator: str
    version: JsSemverVersion

    def matches(self, candidate: JsSemverVersion) -> bool:
        if self.operator == ">=":
            return candidate >= self.version
        if self.operator == "<=":
            return candidate <= self.version
        if self.operator == ">":
            return candidate > self.version
        if self.operator == "<":
            return candidate < self.version
        return candidate == self.version


def parse_js_semver(value: str | None) -> JsSemverVersion | None:
    """Parse one complete SemVer value, ignoring build metadata for precedence."""

    if not value:
        return None
    normalized = value.strip()
    if not normalized or normalized != value or len(normalized) > _MAX_SEMVER_LENGTH:
        return None
    matched = _JS_VERSION_RE.fullmatch(normalized)
    if matched is None:
        return None
    prerelease_raw = matched.group("prerelease")
    prerelease = (
        _parse_identifiers(prerelease_raw, numeric_leading_zero_forbidden=True) if prerelease_raw is not None else None
    )
    if prerelease_raw is not None and prerelease is None:
        return None
    build_raw = matched.group("build")
    if build_raw is not None and _parse_identifiers(build_raw, numeric_leading_zero_forbidden=False) is None:
        return None
    components = tuple(int(matched.group(name)) for name in ("major", "minor", "patch"))
    if any(component > _MAX_SAFE_INTEGER for component in components):
        return None
    return JsSemverVersion(*components, prerelease=prerelease)


def version_matches_js_selector(version: str, selector: str) -> bool:
    """Return whether ``version`` satisfies a supported npm-compatible range.

    Invalid or unsupported syntax invalidates the entire selector.  This is
    intentionally stricter than accepting the valid side of a malformed ``||``
    expression, because this function protects package-resolution decisions.
    """

    parsed_version = parse_js_semver(version)
    if parsed_version is None or len(selector) > _MAX_SELECTOR_LENGTH:
        return False
    normalized_selector = selector.strip()
    if not normalized_selector or normalized_selector == "latest":
        normalized_selector = "*"
    raw_clauses = normalized_selector.split("||")
    if not raw_clauses or len(raw_clauses) > _MAX_SELECTOR_CLAUSES:
        return False
    clauses: list[tuple[_Comparator, ...]] = []
    for raw_clause in raw_clauses:
        clause = _parse_selector_clause(raw_clause.strip())
        if clause is None:
            return False
        clauses.append(clause)
    return any(_comparator_set_matches(parsed_version, clause) for clause in clauses)


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


def _parse_selector_clause(clause: str) -> tuple[_Comparator, ...] | None:
    if not clause or "," in clause:
        return None
    hyphen_match = _HYPHEN_RANGE_RE.fullmatch(clause)
    comparators: list[_Comparator]
    if hyphen_match is not None:
        expanded = _expand_hyphen_range(hyphen_match.group("lower"), hyphen_match.group("upper"))
        if expanded is None:
            return None
        comparators = list(expanded)
    else:
        tokens = clause.split()
        if not tokens or len(tokens) > _MAX_COMPARATORS_PER_CLAUSE:
            return None
        comparators = []
        for token in tokens:
            expanded = _expand_selector_token(token)
            if expanded is None:
                return None
            comparators.extend(expanded)
            if len(comparators) > _MAX_COMPARATORS_PER_CLAUSE:
                return None
    if any(component > _MAX_SAFE_INTEGER for comparator in comparators for component in comparator.version.base):
        # A partial/caret/tilde range can synthesize a successor outside the
        # numeric domain accepted by node-semver even when its input component
        # is itself valid.  Treat that selector as invalid instead of retaining
        # an unrepresentable upper bound.
        return None
    # node-semver removes ``>=0.0.0`` after expanding x/partial ranges.  The
    # comparison is redundant for stable versions, but retaining it would
    # incorrectly exclude 0.0.0 prereleases that another comparator in this
    # same set explicitly admits.
    return tuple(
        comparator
        for comparator in comparators
        if not (comparator.operator == ">=" and comparator.version == JsSemverVersion(0, 0, 0))
    )


def _comparator_set_matches(version: JsSemverVersion, comparators: tuple[_Comparator, ...]) -> bool:
    if not all(comparator.matches(version) for comparator in comparators):
        return False
    if version.prerelease is None:
        return True
    return any(
        comparator.version.prerelease is not None and comparator.version.base == version.base
        for comparator in comparators
    )


def _expand_selector_token(token: str) -> tuple[_Comparator, ...] | None:
    if token.startswith("^"):
        parsed = _parse_range_version(token[1:])
        return _expand_caret(parsed) if parsed is not None else None
    if token.startswith("~"):
        parsed = _parse_range_version(token[1:])
        return _expand_tilde(parsed) if parsed is not None else None
    matched = _COMPARATOR_RE.fullmatch(token)
    if matched is None:
        return None
    operator = matched.group("operator") or ""
    parsed = _parse_range_version(matched.group("version"))
    if parsed is None:
        return None
    return _expand_primitive_comparator(operator, parsed)


def _expand_primitive_comparator(operator: str, parsed: _RangeVersion) -> tuple[_Comparator, ...]:
    lower = parsed.lower_bound()
    if lower is None:
        if operator in {"", "=", ">=", "<="}:
            return ()
        return (_Comparator("<", JsSemverVersion(0, 0, 0, ("0",))),)
    if parsed.complete:
        return (_Comparator(operator or "=", lower),)

    upper = _partial_upper_bound(parsed)
    if operator in {"", "="}:
        return (_Comparator(">=", lower), _Comparator("<", upper))
    if operator == ">=":
        return (_Comparator(">=", lower),)
    if operator == ">":
        return (_Comparator(">=", JsSemverVersion(upper.major, upper.minor, upper.patch)),)
    if operator == "<=":
        return (_Comparator("<", upper),)
    return (_Comparator("<", JsSemverVersion(lower.major, lower.minor, lower.patch, ("0",))),)


def _expand_caret(parsed: _RangeVersion) -> tuple[_Comparator, ...]:
    lower = parsed.lower_bound()
    if lower is None:
        return ()
    if lower.major > 0 or parsed.minor is None:
        upper = JsSemverVersion(lower.major + 1, 0, 0, ("0",))
    elif lower.minor > 0 or parsed.patch is None:
        upper = JsSemverVersion(0, lower.minor + 1, 0, ("0",))
    else:
        upper = JsSemverVersion(0, 0, lower.patch + 1, ("0",))
    return (_Comparator(">=", lower), _Comparator("<", upper))


def _expand_tilde(parsed: _RangeVersion) -> tuple[_Comparator, ...]:
    lower = parsed.lower_bound()
    if lower is None:
        return ()
    if parsed.minor is None:
        upper = JsSemverVersion(lower.major + 1, 0, 0, ("0",))
    else:
        upper = JsSemverVersion(lower.major, lower.minor + 1, 0, ("0",))
    return (_Comparator(">=", lower), _Comparator("<", upper))


def _expand_hyphen_range(lower_raw: str, upper_raw: str) -> tuple[_Comparator, ...] | None:
    lower = _parse_range_version(lower_raw)
    upper = _parse_range_version(upper_raw)
    if lower is None or upper is None:
        return None
    comparators: list[_Comparator] = []
    lower_bound = lower.lower_bound()
    if lower_bound is not None:
        comparators.append(_Comparator(">=", lower_bound))
    upper_bound = upper.lower_bound()
    if upper_bound is not None:
        if upper.complete:
            comparators.append(_Comparator("<=", upper_bound))
        else:
            comparators.append(_Comparator("<", _partial_upper_bound(upper)))
    return tuple(comparators)


def _partial_upper_bound(parsed: _RangeVersion) -> JsSemverVersion:
    if parsed.major is None:
        return JsSemverVersion(0, 0, 0, ("0",))
    if parsed.minor is None:
        return JsSemverVersion(parsed.major + 1, 0, 0, ("0",))
    return JsSemverVersion(parsed.major, parsed.minor + 1, 0, ("0",))


def _parse_range_version(value: str) -> _RangeVersion | None:
    if not value or len(value) > _MAX_SEMVER_LENGTH or value != value.strip():
        return None
    normalized = value[1:] if value.startswith("v") else value
    if not normalized:
        return None
    core_and_prerelease, plus, build = normalized.partition("+")
    if plus and (not build or "+" in build):
        return None
    core, dash, prerelease_raw = core_and_prerelease.partition("-")
    if dash and not prerelease_raw:
        return None
    parts = core.split(".")
    if not 1 <= len(parts) <= 3 or any(not part for part in parts):
        return None
    components: list[int | None] = []
    wildcard_seen = False
    for part in parts:
        if part in _WILDCARDS:
            wildcard_seen = True
            components.append(None)
            continue
        if wildcard_seen or re.fullmatch(_NUMERIC_COMPONENT, part) is None:
            return None
        component = int(part)
        if component > _MAX_SAFE_INTEGER:
            return None
        components.append(component)
    components.extend([None] * (3 - len(components)))
    complete = all(component is not None for component in components)
    prerelease = _parse_identifiers(prerelease_raw, numeric_leading_zero_forbidden=True) if dash else None
    if dash and (not complete or prerelease is None):
        return None
    parsed_build = _parse_identifiers(build, numeric_leading_zero_forbidden=False) if plus else None
    if plus and (not complete or parsed_build is None):
        return None
    return _RangeVersion(components[0], components[1], components[2], prerelease)


def _parse_identifiers(value: str | None, *, numeric_leading_zero_forbidden: bool) -> tuple[str, ...] | None:
    if value is None:
        return None
    identifiers = tuple(value.split("."))
    if not identifiers or any(re.fullmatch(_IDENTIFIER, identifier) is None for identifier in identifiers):
        return None
    if numeric_leading_zero_forbidden and any(
        identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0") for identifier in identifiers
    ):
        return None
    return identifiers


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
