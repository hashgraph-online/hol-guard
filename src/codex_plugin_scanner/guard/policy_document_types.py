"""Shared value types for local policy document adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .models import PolicyDecision


@final
class PolicyCompilationError(ValueError):
    """Raised when a canonical rule cannot map to local PolicyDecision rows."""

    def __init__(self, code: str, rule_id: str) -> None:
        self.code = code
        self.rule_id = rule_id
        super().__init__(f"{code}: {rule_id}")


@dataclass(frozen=True)
class CompiledPolicyRow:
    decision: PolicyDecision
    rule_id: str
    provenance_json: str


@dataclass(frozen=True, slots=True)
class PolicyDocumentDiff:
    changed: bool
    text: str
    additions: tuple[str, ...]
    modifications: tuple[str, ...]
    removals: tuple[str, ...]
    impacted_scopes: tuple[str, ...]
    impacted_harnesses: tuple[str, ...]
    impacted_artifact_families: tuple[str, ...]
    conflict_warnings: tuple[str, ...]
    broadened_rules: tuple[str, ...] = ()
    narrowed_rules: tuple[str, ...] = ()
    unchanged_rules: tuple[str, ...] = ()
    effective_action_changes: tuple[str, ...] = ()
    broad_relaxing_changes: tuple[str, ...] = ()
