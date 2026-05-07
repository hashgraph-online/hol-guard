"""Advisory matchers for multi-source threat intelligence.

Each matcher takes a ThreatAdvisory and a target dict, and returns True if
the advisory applies to the target. Matchers are keyed by their `matcher`
field value in the advisory.
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

from .threat_intel import ThreatAdvisory


@runtime_checkable
class AdvisoryMatcher(Protocol):
    """Callable that tests an advisory against a target dict."""

    def __call__(self, advisory: ThreatAdvisory, target: dict[str, object]) -> bool: ...


def _norm(val: object) -> str:
    if not isinstance(val, str):
        return ""
    return val.strip().lower()


def _package_matches(advisory_pkg: str, target_pkg: str) -> bool:
    if not advisory_pkg or not target_pkg:
        return False
    return _norm(advisory_pkg) == _norm(target_pkg)


def match_osv(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Match OSV advisories by package name and ecosystem."""
    pkg_name = target.get("package_name")
    ecosystem = target.get("ecosystem")
    advisory_pkg = advisory.matcher.split(":", 1)[-1] if ":" in advisory.matcher else advisory.matcher
    advisory_eco = advisory.source.split("/", 1)[0] if "/" in advisory.source else advisory.source
    eco_match = not ecosystem or _norm(advisory_eco) in (_norm(str(ecosystem)), "osv", "*")
    return eco_match and _package_matches(advisory_pkg, str(pkg_name or ""))


def match_github_advisory(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Match GitHub Security Advisory by GHSA ID or package name."""
    matcher_val = advisory.matcher
    if re.match(r"^GHSA-", matcher_val, re.IGNORECASE):
        ghsa_id = target.get("ghsa_id")
        return isinstance(ghsa_id, str) and _norm(ghsa_id) == _norm(matcher_val)
    return _package_matches(matcher_val, str(target.get("package_name") or ""))


def match_nvd_cve(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Match NVD CVE by CVE ID or harness name."""
    matcher_val = advisory.matcher
    if re.match(r"^CVE-", matcher_val, re.IGNORECASE):
        cve_id = target.get("cve_id")
        return isinstance(cve_id, str) and _norm(cve_id) == _norm(matcher_val)
    harness = target.get("harness")
    return isinstance(harness, str) and _norm(harness) == _norm(matcher_val)


def match_npm_advisory(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Match npm advisory by package name when ecosystem is npm."""
    eco = target.get("ecosystem")
    if not isinstance(eco, str) or _norm(eco) not in ("npm",):
        return False
    return _package_matches(advisory.matcher, str(target.get("package_name") or ""))


def match_pypi_advisory(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Match PyPI advisory by package name when ecosystem is pypi."""
    eco = target.get("ecosystem")
    if not isinstance(eco, str) or _norm(eco) not in ("pypi", "pip"):
        return False
    return _package_matches(advisory.matcher, str(target.get("package_name") or ""))


def match_github_action(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Match a GitHub Action by action slug (owner/name)."""
    action_slug = target.get("action_slug")
    if not isinstance(action_slug, str):
        return False
    return _norm(advisory.matcher) == _norm(action_slug)


def match_mcp_server(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Match an MCP server advisory by server name or URL fragment."""
    server_name = target.get("mcp_server")
    if not isinstance(server_name, str):
        return False
    matcher_norm = _norm(advisory.matcher)
    return matcher_norm in _norm(server_name) or _norm(server_name) == matcher_norm


def match_skill_hash(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Match a skill (extension/tool) by its content hash."""
    skill_hash = target.get("skill_hash")
    if not isinstance(skill_hash, str):
        return False
    return _norm(advisory.matcher) == _norm(skill_hash)


def match_malicious_domain(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Match a network destination against a known-malicious domain."""
    hosts: object = target.get("network_hosts")
    if not isinstance(hosts, list):
        hosts = [target.get("network_host")] if target.get("network_host") else []
    matcher_norm = _norm(advisory.matcher)
    return any(matcher_norm in _norm(str(h)) for h in hosts if h)


def match_malicious_package_hash(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Match a package by its content hash (e.g., tarball SHA256)."""
    pkg_hash = target.get("package_hash")
    if not isinstance(pkg_hash, str):
        return False
    return _norm(advisory.matcher) == _norm(pkg_hash)


_MATCHER_REGISTRY: dict[str, AdvisoryMatcher] = {
    "osv": match_osv,
    "github_advisory": match_github_advisory,
    "nvd_cve": match_nvd_cve,
    "npm": match_npm_advisory,
    "pypi": match_pypi_advisory,
    "github_action": match_github_action,
    "mcp_server": match_mcp_server,
    "skill_hash": match_skill_hash,
    "malicious_domain": match_malicious_domain,
    "malicious_package_hash": match_malicious_package_hash,
}


def get_matcher(matcher_key: str) -> AdvisoryMatcher | None:
    """Return the matcher function for a given matcher key, or None if unknown."""
    return _MATCHER_REGISTRY.get(matcher_key)


def apply_advisory(advisory: ThreatAdvisory, target: dict[str, object]) -> bool:
    """Test a single advisory against a target using the registered matcher.

    Dispatcher reads the advisory `source` field to select the matcher function.
    Returns False for unknown source keys (safe default — no false positives).
    """
    source_key = advisory.source.split("/")[0].lower()
    matcher_fn = get_matcher(source_key)
    if matcher_fn is None:
        return False
    return matcher_fn(advisory, target)


def match_all_advisories(
    advisories: tuple[ThreatAdvisory, ...],
    target: dict[str, object],
) -> tuple[ThreatAdvisory, ...]:
    """Return all advisories from the bundle that match the given target."""
    return tuple(a for a in advisories if apply_advisory(a, target))
