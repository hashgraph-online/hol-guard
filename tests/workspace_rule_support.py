"""Single-detector views of ``rule_findings`` for the workspace rule tests."""

from __future__ import annotations

from codex_plugin_scanner.guard.workspace_rule_findings import rule_findings


def project_rule_findings(detector: str, result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of one native rule result."""

    return rule_findings({}, [(detector, result)])[0]


def with_rule_coverage(detector: str, coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add one rule detector to a run's coverage."""

    return rule_findings(coverage, [(detector, result)])[1]
