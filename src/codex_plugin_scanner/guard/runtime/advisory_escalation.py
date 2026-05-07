"""Advisory-driven policy escalation for Guard decisions.

When a cached threat intelligence bundle contains a critical advisory that
matches the current artifact, a lower-severity policy action such as ``allow``
or ``warn`` can be escalated to ``ask`` or ``block`` to ensure the user
reviews the risk before the action proceeds.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from codex_plugin_scanner.guard.models import GuardAction
    from codex_plugin_scanner.guard.runtime.threat_intel import ThreatAdvisory

_ESCALATION_TABLE: dict[str, dict[str, str]] = {
    "critical": {
        "allow": "ask",
        "warn": "ask",
        "review": "block",
    },
    "high": {
        "allow": "ask",
        "warn": "ask",
    },
}

_ESCALATION_THRESHOLD_SEVERITIES = frozenset({"critical", "high"})


def escalate_for_advisories(
    policy_action: GuardAction,
    matched_advisories: tuple[ThreatAdvisory, ...],
) -> tuple[GuardAction, str | None]:
    """Return the escalated policy action and the advisory id that triggered it.

    If no advisory warrants escalation, returns the original action and None.
    The most severe advisory match drives escalation; within the same severity
    the first match in the input tuple wins.
    """
    if not matched_advisories:
        return policy_action, None

    ranked = sorted(
        (a for a in matched_advisories if a.severity.lower() in _ESCALATION_THRESHOLD_SEVERITIES),
        key=lambda a: 0 if a.severity.lower() == "critical" else 1,
    )

    for advisory in ranked:
        escalation_map = _ESCALATION_TABLE.get(advisory.severity.lower(), {})
        escalated = escalation_map.get(policy_action)
        if escalated is not None:
            return escalated, advisory.advisory_id  # type: ignore[return-value]

    return policy_action, None


def advisory_match_summary(matched_advisories: tuple[ThreatAdvisory, ...]) -> str:
    """Return a brief human-readable summary of matched advisories for logging."""
    if not matched_advisories:
        return "no advisory matches"
    parts = [f"{a.advisory_id}({a.severity.lower()})" for a in matched_advisories[:5]]
    suffix = f" +{len(matched_advisories) - 5} more" if len(matched_advisories) > 5 else ""
    return ", ".join(parts) + suffix
