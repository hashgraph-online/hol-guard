"""Reconstruct a portable rule only when its stored selector product is exact."""

from __future__ import annotations

import json
from collections.abc import Mapping
from math import prod
from typing import cast

from .policy_document_types import PolicyCompilationError

_SELECTORS = ("artifacts", "harnesses", "publishers", "workspaces")
_LOCAL_SELECTOR_FIELDS = ("harness", "publisher", "workspace")


def _local_extension(rule: Mapping[str, object]) -> dict[str, object]:
    value = rule.get("x-hol-local")
    return dict(cast(Mapping[str, object], value)) if isinstance(value, Mapping) else {}


def _non_selector_content(rule: Mapping[str, object]) -> str:
    content = dict(rule)
    content.pop("match", None)
    extension = _local_extension(content)
    for name in _LOCAL_SELECTOR_FIELDS:
        extension.pop(name, None)
    content["x-hol-local"] = extension
    return json.dumps(content, sort_keys=True, separators=(",", ":"))


def coalesce_exported_rules(rules: list[dict[str, object]]) -> list[dict[str, object]]:
    """Preserve original rule IDs without turning sparse rows into new grants."""
    grouped: dict[str, list[dict[str, object]]] = {}
    for rule in rules:
        grouped.setdefault(str(rule["id"]), []).append(rule)
    result: list[dict[str, object]] = []
    for rule_id, group in grouped.items():
        if len(group) == 1:
            result.append(group[0])
            continue
        if len({_non_selector_content(rule) for rule in group}) != 1:
            raise PolicyCompilationError("policy_rule_export_conflict", rule_id)
        selector_rows: set[tuple[str | None, ...]] = set()
        for rule in group:
            match = cast(dict[str, list[str]], rule["match"])
            assert isinstance(match, dict)
            # Stored wildcard harnesses are exported without a match entry. Restore
            # that explicit selector before checking the original product, so a
            # wildcard can coexist with a named harness without widening any row.
            selectors: list[str | None] = []
            for name in _SELECTORS:
                default = "*" if name == "harnesses" else None
                selectors.append(match[name][0] if name in match else default)
            selector_rows.add(tuple(selectors))
        dimensions = [{values[index] for values in selector_rows} for index in range(len(_SELECTORS))]
        if any(None in dimension and len(dimension) > 1 for dimension in dimensions):
            raise PolicyCompilationError("policy_rule_export_conflict", rule_id)
        if prod(len(dimension) for dimension in dimensions) != len(selector_rows):
            raise PolicyCompilationError("policy_rule_export_sparse_selectors", rule_id)
        merged = dict(group[0])
        merged["match"] = {
            name: sorted(value for value in dimension if value is not None)
            for name, dimension in zip(_SELECTORS, dimensions, strict=True)
            if dimension != {None}
        }
        extension = _local_extension(merged)
        for field, selector in (("harness", "harnesses"), ("publisher", "publishers"), ("workspace", "workspaces")):
            if len(dimensions[_SELECTORS.index(selector)]) > 1:
                extension.pop(field, None)
        merged["x-hol-local"] = extension
        result.append(merged)
    return result
