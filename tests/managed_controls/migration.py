"""Deterministic compatibility mapping for legacy contextual policies."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LegacyRuleMapping:
    rule_id: str
    extension_id: str | None
    permission_id: str | None
    advanced_raw_rule: bool


def map_legacy_rule(
    rule_id: str,
    *,
    known_permission: tuple[str, str] | None,
) -> LegacyRuleMapping:
    if known_permission is None:
        return LegacyRuleMapping(rule_id, None, None, True)
    extension_id, permission_id = known_permission
    return LegacyRuleMapping(
        rule_id,
        extension_id,
        permission_id,
        False,
    )


def preserve_legacy_policy_document(document: dict[str, object]) -> dict[str, object]:
    """Return legacy policy data unchanged unless a versioned migration is explicit."""

    return dict(document)
