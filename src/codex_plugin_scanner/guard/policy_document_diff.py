"""Semantic and textual comparisons for canonical Guard policies."""

from __future__ import annotations

import difflib
import itertools
from datetime import datetime

from .policy_document import GuardPolicyDocument, PolicyRule
from .policy_document_types import PolicyDocumentDiff
from .policy_document_yaml import format_policy_document_yaml


def _artifact_family(value: str) -> str:
    for separator in (":", "/"):
        if separator in value:
            return value.split(separator, 1)[0]
    return value


def _semantic_policy_diff(
    baseline: GuardPolicyDocument,
    candidate: GuardPolicyDocument,
) -> tuple[
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    baseline_rules = {rule.id: rule for rule in baseline.rules}
    candidate_rules = {rule.id: rule for rule in candidate.rules}
    additions = tuple(sorted(candidate_rules.keys() - baseline_rules.keys()))
    removals = tuple(sorted(baseline_rules.keys() - candidate_rules.keys()))
    modifications = tuple(
        sorted(
            rule_id
            for rule_id in baseline_rules.keys() & candidate_rules.keys()
            if baseline_rules[rule_id].to_mapping() != candidate_rules[rule_id].to_mapping()
        )
    )
    changed_ids = set(additions) | set(modifications) | set(removals)
    impacted_rules = [
        rule
        for rule_id in sorted(changed_ids)
        for rule in (candidate_rules.get(rule_id) or baseline_rules.get(rule_id),)
        if rule is not None
    ]
    impacted_scopes = {field for rule in impacted_rules for field, values in rule.match.fields if values}
    impacted_harnesses = {
        value
        for rule in impacted_rules
        for field, values in rule.match.fields
        if field == "harnesses"
        for value in values
    }
    impacted_artifact_families = {
        _artifact_family(value)
        for rule in impacted_rules
        for field, values in rule.match.fields
        if field == "artifacts"
        for value in values
    }
    enabled_candidate_rules = [rule for rule in candidate.rules if rule.enabled]
    conflict_warnings = tuple(
        sorted(
            f"overlapping_effects:{left.id}:{right.id}"
            for left, right in itertools.combinations(enabled_candidate_rules, 2)
            if left.effect != right.effect and _matches_overlap(left, right)
        )
    )
    return (
        additions,
        modifications,
        removals,
        tuple(sorted(impacted_scopes)),
        tuple(sorted(impacted_harnesses)),
        tuple(sorted(impacted_artifact_families)),
        conflict_warnings,
    )


def _match_fields(rule: PolicyRule) -> dict[str, frozenset[str]]:
    return {field: frozenset(values) for field, values in rule.match.fields if values}


def _match_contains(container: PolicyRule, contained: PolicyRule) -> bool:
    container_fields = _match_fields(container)
    contained_fields = _match_fields(contained)
    return all(
        field in contained_fields and values.issuperset(contained_fields[field])
        for field, values in container_fields.items()
    )


def _matches_overlap(left: PolicyRule, right: PolicyRule) -> bool:
    left_fields = _match_fields(left)
    right_fields = _match_fields(right)
    return all(bool(left_fields[field] & right_fields[field]) for field in left_fields.keys() & right_fields.keys())


def _restrictive_lifetime_relaxed(previous: PolicyRule, current: PolicyRule) -> bool:
    if previous.lifetime == current.lifetime:
        return False
    if previous.lifetime.mode == "permanent":
        return current.lifetime.mode != "permanent"
    if current.lifetime.mode == "permanent":
        return False
    if previous.lifetime.mode != current.lifetime.mode:
        return True
    previous_expiry = previous.lifetime.expires_at
    current_expiry = current.lifetime.expires_at
    if previous_expiry is None:
        return current_expiry is not None
    if current_expiry is None:
        return False
    return datetime.fromisoformat(current_expiry.replace("Z", "+00:00")) < datetime.fromisoformat(
        previous_expiry.replace("Z", "+00:00")
    )


_DEFAULT_ENFORCEMENT_STRENGTH = {
    "allow": 0,
    "ignore": 0,
    "observe": 0,
    "warn": 1,
    "review": 1,
    "prompt": 1,
    "require-reapproval": 2,
    "block": 3,
    "enforce": 3,
}


def _classify_default_changes(
    baseline: GuardPolicyDocument,
    candidate: GuardPolicyDocument,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    baseline_defaults = baseline.defaults.to_mapping()
    candidate_defaults = candidate.defaults.to_mapping()
    changes: list[str] = []
    broad_relaxing: list[str] = []
    for key in sorted(baseline_defaults.keys() | candidate_defaults.keys()):
        previous = baseline_defaults.get(key)
        current = candidate_defaults.get(key)
        if previous == current:
            continue
        changes.append(f"defaults.{key}:{previous}->{current}")
        previous_strength = _DEFAULT_ENFORCEMENT_STRENGTH.get(previous) if isinstance(previous, str) else None
        current_strength = _DEFAULT_ENFORCEMENT_STRENGTH.get(current) if isinstance(current, str) else None
        if previous_strength is not None and current_strength is not None and current_strength < previous_strength:
            broad_relaxing.append(f"defaults.{key}")
    return tuple(changes), tuple(broad_relaxing)


def _classify_rule_changes(
    baseline: GuardPolicyDocument,
    candidate: GuardPolicyDocument,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    baseline_rules = {rule.id: rule for rule in baseline.rules}
    candidate_rules = {rule.id: rule for rule in candidate.rules}
    shared_ids = baseline_rules.keys() & candidate_rules.keys()
    broadened: list[str] = []
    narrowed: list[str] = []
    unchanged: list[str] = []
    action_changes: list[str] = []
    broad_relaxing: list[str] = []
    restrictive_effects = frozenset({"block", "review"})
    relaxing_effects = frozenset({"allow", "ignore"})

    for rule_id in sorted(shared_ids):
        previous = baseline_rules[rule_id]
        current = candidate_rules[rule_id]
        if previous.to_mapping() == current.to_mapping():
            unchanged.append(rule_id)
            continue
        current_contains_previous = _match_contains(current, previous)
        previous_contains_current = _match_contains(previous, current)
        if current_contains_previous and not previous_contains_current:
            broadened.append(rule_id)
        elif previous_contains_current and not current_contains_previous:
            narrowed.append(rule_id)
        if previous.effect != current.effect or previous.enabled != current.enabled:
            action_changes.append(
                f"{rule_id}:{previous.effect if previous.enabled else 'disabled'}"
                f"->{current.effect if current.enabled else 'disabled'}"
            )
        relaxes_effect = (
            previous.enabled
            and previous.effect in restrictive_effects
            and (not current.enabled or current.effect in relaxing_effects)
        )
        relaxes_lifetime = (
            previous.enabled
            and current.enabled
            and previous.effect in restrictive_effects
            and current.effect in restrictive_effects
            and _restrictive_lifetime_relaxed(previous, current)
        )
        if (
            relaxes_effect
            or relaxes_lifetime
            or (
                current.enabled
                and current.effect in relaxing_effects
                and current_contains_previous
                and not previous_contains_current
            )
        ):
            broad_relaxing.append(rule_id)

    for rule_id in sorted(candidate_rules.keys() - baseline_rules.keys()):
        current = candidate_rules[rule_id]
        if current.enabled and current.effect in relaxing_effects:
            broad_relaxing.append(rule_id)
    for rule_id in sorted(baseline_rules.keys() - candidate_rules.keys()):
        previous = baseline_rules[rule_id]
        if previous.enabled and previous.effect in restrictive_effects:
            broad_relaxing.append(rule_id)

    default_changes, default_relaxing = _classify_default_changes(baseline, candidate)
    action_changes.extend(default_changes)
    broad_relaxing.extend(default_relaxing)
    return (
        tuple(broadened),
        tuple(narrowed),
        tuple(unchanged),
        tuple(action_changes),
        tuple(sorted(set(broad_relaxing))),
    )


def diff_policy_documents(
    baseline: GuardPolicyDocument,
    candidate: GuardPolicyDocument,
    *,
    baseline_name: str = "baseline",
    candidate_name: str = "candidate",
) -> PolicyDocumentDiff:
    baseline_text = format_policy_document_yaml(baseline)
    candidate_text = format_policy_document_yaml(candidate)
    lines = difflib.unified_diff(
        baseline_text.splitlines(keepends=True),
        candidate_text.splitlines(keepends=True),
        fromfile=baseline_name,
        tofile=candidate_name,
    )
    text = "".join(lines)
    (
        additions,
        modifications,
        removals,
        impacted_scopes,
        impacted_harnesses,
        impacted_artifact_families,
        conflict_warnings,
    ) = _semantic_policy_diff(baseline, candidate)
    (
        broadened_rules,
        narrowed_rules,
        unchanged_rules,
        effective_action_changes,
        broad_relaxing_changes,
    ) = _classify_rule_changes(baseline, candidate)
    return PolicyDocumentDiff(
        changed=bool(text),
        text=text,
        additions=additions,
        modifications=modifications,
        removals=removals,
        impacted_scopes=impacted_scopes,
        impacted_harnesses=impacted_harnesses,
        impacted_artifact_families=impacted_artifact_families,
        conflict_warnings=conflict_warnings,
        broadened_rules=broadened_rules,
        narrowed_rules=narrowed_rules,
        unchanged_rules=unchanged_rules,
        effective_action_changes=effective_action_changes,
        broad_relaxing_changes=broad_relaxing_changes,
    )
