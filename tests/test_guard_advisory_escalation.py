"""Tests for advisory-driven policy escalation — T557."""

from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.advisory_escalation import (
    advisory_match_summary,
    escalate_for_advisories,
)
from codex_plugin_scanner.guard.runtime.threat_intel import ThreatAdvisory


def _advisory(
    advisory_id: str,
    severity: str,
    source: str = "osv/npm",
    matcher: str = "evil-pkg",
) -> ThreatAdvisory:
    return ThreatAdvisory(
        advisory_id=advisory_id,
        title=f"Test advisory {advisory_id}",
        severity=severity,
        source=source,
        affected_type="package",
        matcher=matcher,
        recommendation="upgrade",
    )


CRITICAL = _advisory("GHSA-crit-01", "critical")
HIGH = _advisory("GHSA-high-01", "high")
MEDIUM = _advisory("GHSA-med-01", "medium")
LOW = _advisory("GHSA-low-01", "low")
INFO = _advisory("GHSA-info-01", "info")


@pytest.mark.parametrize(
    ("policy_action", "advisories", "expected_action", "expect_advisory"),
    [
        ("allow", (CRITICAL,), "ask", True),
        ("warn", (CRITICAL,), "ask", True),
        ("review", (CRITICAL,), "block", True),
        ("allow", (HIGH,), "ask", True),
        ("warn", (HIGH,), "ask", True),
        ("review", (HIGH,), "review", False),
        ("allow", (MEDIUM,), "allow", False),
        ("allow", (LOW,), "allow", False),
        ("allow", (INFO,), "allow", False),
        ("block", (CRITICAL,), "block", False),
        ("allow", (), "allow", False),
        ("warn", (), "warn", False),
    ],
)
def test_escalate_for_advisories(
    policy_action: str,
    advisories: tuple[ThreatAdvisory, ...],
    expected_action: str,
    expect_advisory: bool,
) -> None:
    escalated, triggering_id = escalate_for_advisories(policy_action, advisories)  # type: ignore[arg-type]
    assert escalated == expected_action
    if expect_advisory:
        assert triggering_id is not None
    else:
        assert triggering_id is None


def test_escalate_critical_beats_high() -> None:
    escalated, triggering_id = escalate_for_advisories(
        "allow",  # type: ignore[arg-type]
        (HIGH, CRITICAL),
    )
    assert escalated == "ask"
    assert triggering_id == CRITICAL.advisory_id


def test_escalate_no_advisories_returns_original() -> None:
    assert escalate_for_advisories("allow", ())[0] == "allow"  # type: ignore[arg-type]
    assert escalate_for_advisories("block", ())[0] == "block"  # type: ignore[arg-type]


def test_advisory_match_summary_empty() -> None:
    assert advisory_match_summary(()) == "no advisory matches"


def test_advisory_match_summary_single() -> None:
    summary = advisory_match_summary((CRITICAL,))
    assert "GHSA-crit-01" in summary
    assert "critical" in summary


def test_advisory_match_summary_truncates_beyond_five() -> None:
    advisories = tuple(_advisory(f"ID-{i}", "medium") for i in range(10))
    summary = advisory_match_summary(advisories)
    assert "+5 more" in summary


def test_advisory_match_summary_exactly_five() -> None:
    advisories = tuple(_advisory(f"ID-{i}", "medium") for i in range(5))
    summary = advisory_match_summary(advisories)
    assert "more" not in summary
