"""Bind npm policy-range evaluation to the package version that will run."""

from __future__ import annotations

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .js_semver import version_matches_js_selector


def policy_selector_matches_target(selector: str, target: dict[str, object]) -> bool:
    """Match policy selectors using the target ecosystem's range grammar."""

    version = _optional_string(target.get("version"))
    requested_range = _optional_string(target.get("range"))
    ecosystem = _optional_string(target.get("ecosystem")) or "npm"
    if ecosystem == "npm":
        if version is None:
            return requested_range is not None and requested_range == selector
        return version_matches_js_selector(version, selector)
    if requested_range is not None and requested_range == selector:
        return True
    if version is None:
        return False
    if selector in {version, f"={version}", f"=={version}"}:
        return True
    try:
        return Version(version) in SpecifierSet(selector)
    except (InvalidSpecifier, InvalidVersion):
        return False


def target_for_resolved_npm_policy_match(
    target: dict[str, object],
    *,
    resolved_version: str | None,
) -> dict[str, object]:
    """Return a policy-only target whose selector input is the resolved npm version.

    Package intent retains the user-requested range for receipts and prompts.
    Policy matching must instead evaluate the lockfile/registry version that is
    actually selected; otherwise an allow rule can match the requested range's
    text while npm resolves an inadmissible prerelease.
    """

    ecosystem_value = target.get("ecosystem")
    ecosystem = ecosystem_value.strip() if isinstance(ecosystem_value, str) else "npm"
    if resolved_version is None or (ecosystem or "npm") != "npm":
        return target
    policy_target = dict(target)
    policy_target["version"] = resolved_version
    policy_target["range"] = None
    return policy_target


def bind_resolved_npm_policy_result(
    package: dict[str, object],
    *,
    resolved_version: str | None,
) -> dict[str, object]:
    """Record the exact npm version without replacing the requested range."""

    if resolved_version is None:
        return package
    bound = dict(package)
    bound["resolvedVersion"] = resolved_version
    return bound


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None
