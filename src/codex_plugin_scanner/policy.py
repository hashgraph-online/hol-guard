"""Policy profile evaluation for scan/lint gating."""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.models import SEVERITY_ORDER, Finding, Severity


@dataclass(frozen=True, slots=True)
class PolicyProfile:
    name: str
    max_severity: Severity
    required_rules: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    profile: str
    policy_pass: bool
    max_observed_severity: Severity | None
    severity_failures: tuple[str, ...]
    missing_required_rules: tuple[str, ...]


POLICY_PROFILES: dict[str, PolicyProfile] = {
    "default": PolicyProfile(name="default", max_severity=Severity.CRITICAL),
    "public-marketplace": PolicyProfile(name="public-marketplace", max_severity=Severity.MEDIUM),
    "strict-security": PolicyProfile(name="strict-security", max_severity=Severity.LOW),
}


def evaluate_policy(findings: tuple[Finding, ...], profile_name: str) -> PolicyEvaluation:
    profile = POLICY_PROFILES.get(profile_name, POLICY_PROFILES["default"])
    max_observed = max(findings, key=lambda finding: SEVERITY_ORDER[finding.severity]).severity if findings else None

    severity_failures = tuple(
        finding.rule_id
        for finding in findings
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[profile.max_severity]
    )

    present_rule_ids = {finding.rule_id for finding in findings}
    missing_required = tuple(rule_id for rule_id in profile.required_rules if rule_id not in present_rule_ids)

    return PolicyEvaluation(
        profile=profile.name,
        policy_pass=not severity_failures and not missing_required,
        max_observed_severity=max_observed,
        severity_failures=severity_failures,
        missing_required_rules=missing_required,
    )


def resolve_profile(profile_name: str | None) -> str:
    if not profile_name:
        return "default"
    normalized = profile_name.strip().lower()
    return normalized if normalized in POLICY_PROFILES else "default"
