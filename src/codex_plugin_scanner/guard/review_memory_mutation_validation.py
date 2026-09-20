"""Validate signed decision-memory mutation identifiers before changing authority."""

from __future__ import annotations

from typing import cast

from .review_oauth_binding import GuardReviewContractError


def _identifier(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_decision_memory_mutation_ids(bundle: dict[str, object]) -> None:
    """Reject malformed mutation identities; absent optional revocations remain valid."""
    rules = bundle.get("memoryRules")
    if not isinstance(rules, list):
        raise GuardReviewContractError("decision_memory_rules_missing")
    for rule in cast(list[object], rules):
        if not isinstance(rule, dict):
            raise GuardReviewContractError("decision_memory_rule_invalid")
        if not _identifier(cast(dict[str, object], rule).get("ruleId")):
            raise GuardReviewContractError("invalid_decision_memory_rule")
    revocations = bundle.get("revocations", [])
    if not isinstance(revocations, list) or any(
        not _identifier(rule_id) for rule_id in cast(list[object], revocations)
    ):
        raise GuardReviewContractError("invalid_decision_memory_revocation")
