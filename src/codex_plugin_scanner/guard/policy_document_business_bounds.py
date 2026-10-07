"""Draft transport bounds; Rust still owns business semantics and enforcement."""

from __future__ import annotations

import json

# guard-policy-snapshot::business_match::BUSINESS_POLICY_MATCH_MAX_BYTES.
MAX_BUSINESS_SELECTOR_BYTES = 64 * 1024


def oversized_business_selector_path(value: dict[str, object]) -> tuple[str | int, ...] | None:
    """Inspect schema-validated selectors without returning their content."""
    spec = value.get("spec")
    if not isinstance(spec, dict):
        return None
    rules = spec.get("rules")
    if not isinstance(rules, list):
        return None
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        match = rule.get("match")
        if not isinstance(match, dict) or not isinstance(match.get("business"), dict):
            continue
        encoded = json.dumps(match["business"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_BUSINESS_SELECTOR_BYTES:
            return ("spec", "rules", index, "match", "business")
    return None
