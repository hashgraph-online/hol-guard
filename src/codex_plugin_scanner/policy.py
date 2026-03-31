"""Policy profile evaluation for scan/lint gating."""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.models import SEVERITY_ORDER, Finding, Severity


@dataclass(frozen=True, slots=True)
class PolicyProfile:
    name: str
    max_severity: Severity
    required_executed_rules: tuple[str, ...] = ()
    required_pass_rules: tuple[str, ...] = ()
    min_score: int = 0


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    rule_id: str
    executed: bool
    triggered: bool
    passed: bool


@dataclass(frozen=True, slots=True)
class PolicyEvaluation:
    profile: str
    policy_pass: bool
    max_observed_severity: Severity | None
    severity_failures: tuple[str, ...]
    missing_required_rules: tuple[str, ...]
    failed_required_pass_rules: tuple[str, ...]


POLICY_PROFILES: dict[str, PolicyProfile] = {
    "default": PolicyProfile(name="default", max_severity=Severity.CRITICAL, min_score=0),
    "public-marketplace": PolicyProfile(name="public-marketplace", max_severity=Severity.MEDIUM, min_score=60),
    "strict-security": PolicyProfile(name="strict-security", max_severity=Severity.LOW, min_score=80),
}


def build_rule_inventory(findings: tuple[Finding, ...], executed_rule_ids: set[str]) -> dict[str, RuleEvaluation]:
    triggered_ids = {finding.rule_id for finding in findings}
    inventory: dict[str, RuleEvaluation] = {}
    for rule_id in executed_rule_ids | triggered_ids:
        triggered = rule_id in triggered_ids
        inventory[rule_id] = RuleEvaluation(
            rule_id=rule_id,
            executed=rule_id in executed_rule_ids,
            triggered=triggered,
            passed=not triggered,
        )
    return inventory


def evaluate_policy(
    findings: tuple[Finding, ...],
    profile_name: str,
    *,
    rule_inventory: dict[str, RuleEvaluation] | None = None,
) -> PolicyEvaluation:
    profile = POLICY_PROFILES.get(profile_name, POLICY_PROFILES["default"])
    max_observed = max(findings, key=lambda finding: SEVERITY_ORDER[finding.severity]).severity if findings else None

    severity_failures = tuple(
        finding.rule_id
        for finding in findings
        if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[profile.max_severity]
    )

    inventory = rule_inventory or build_rule_inventory(findings, set())
    missing_required = tuple(rule_id for rule_id in profile.required_executed_rules if not inventory.get(rule_id, RuleEvaluation(rule_id, False, False, True)).executed)
    failed_required_pass = tuple(rule_id for rule_id in profile.required_pass_rules if not inventory.get(rule_id, RuleEvaluation(rule_id, False, False, True)).passed)

    return PolicyEvaluation(
        profile=profile.name,
        policy_pass=not severity_failures and not missing_required and not failed_required_pass,
        max_observed_severity=max_observed,
        severity_failures=severity_failures,
        missing_required_rules=missing_required,
        failed_required_pass_rules=failed_required_pass,
    )


def resolve_profile(profile_name: str | None) -> str:
    if not profile_name:
        return "default"
    normalized = profile_name.strip().lower()
    return normalized if normalized in POLICY_PROFILES else "default"
