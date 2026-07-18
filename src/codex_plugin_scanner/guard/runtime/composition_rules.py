"""Signal composition rules for Guard detector action decisions.

Combines false-positive advisory signals with risk signals to produce a
calibrated canonical Guard action recommendation.

The base policy action (from config/approval policy) is used as the starting
point. Composition rules may downgrade ``block`` to ``review`` or ``review``
to ``warn`` when strong false-positive evidence is present, and may upgrade
weaker actions when high-confidence risk signals demand it. Explicit
``require-reapproval`` and ``sandbox-required`` requirements are never lowered.

Composition rules never override an explicit user policy choice.
"""

from __future__ import annotations

from dataclasses import dataclass

from codex_plugin_scanner.guard.action_lattice import (
    guard_action_severity,
    most_restrictive_guard_action,
    normalize_guard_action_result,
)
from codex_plugin_scanner.guard.models import SEVERITY_RANK, GuardAction
from codex_plugin_scanner.guard.runtime.signals import RiskSignalV2

_DOWNGRADE_BLOCK_CATEGORIES = frozenset({"bypass", "persistence"})
_DOWNGRADE_PROTECTED_SEVERITIES = frozenset({"critical", "high"})
_FP_DOWNGRADE_MAX_SEVERITY = frozenset({"info", "low"})


@dataclass(frozen=True, slots=True)
class CompositionResult:
    """Result of applying composition rules to a set of signals."""

    action: GuardAction
    reason: str
    downgraded: bool
    upgraded: bool
    normalization_reason_code: str | None = None
    original_action: str | None = None


def compose_action_from_signals(
    signals: tuple[RiskSignalV2, ...],
    base_action: object,
) -> CompositionResult:
    """Apply composition rules to signals and return a calibrated action.

    Args:
        signals: All signals from the detector run (risk + advisory).
        base_action: The starting action from config/policy evaluation.

    Returns:
        A ``CompositionResult`` with the final action and an explanation.
    """
    base_normalization = normalize_guard_action_result(base_action, unknown_action="block")
    normalized_base_action = base_normalization.action
    risk_signals = tuple(s for s in signals if s.category != "false_positive")
    fp_signals = tuple(s for s in signals if s.category == "false_positive")

    if not signals:
        return CompositionResult(
            action=normalized_base_action,
            reason="no detector signals; base policy action applies",
            downgraded=False,
            upgraded=False,
            normalization_reason_code=base_normalization.reason_code,
            original_action=base_normalization.original_action,
        )

    current_action = normalized_base_action
    upgrade_reason: str | None = None
    downgrade_reason: str | None = None

    for signal in risk_signals:
        if signal.category == "bypass" and signal.confidence in ("likely", "strong"):
            upgraded_action = most_restrictive_guard_action(current_action, "block")
            if guard_action_severity(upgraded_action) > guard_action_severity(current_action):
                upgrade_reason = f"bypass signal '{signal.detector}' forces block"
                current_action = upgraded_action

        if signal.category == "persistence" and signal.severity in ("high", "critical"):
            upgraded_action = most_restrictive_guard_action(current_action, "review")
            if guard_action_severity(upgraded_action) > guard_action_severity(current_action):
                upgrade_reason = upgrade_reason or f"persistence signal '{signal.detector}' requires review"
                current_action = upgraded_action

        if signal.severity == "critical" and signal.confidence in ("likely", "strong"):
            upgraded_action = most_restrictive_guard_action(current_action, "block")
            if guard_action_severity(upgraded_action) > guard_action_severity(current_action):
                upgrade_reason = upgrade_reason or f"critical signal '{signal.detector}' forces block"
                current_action = upgraded_action

    final_action = current_action

    if fp_signals and not upgrade_reason and base_normalization.recognized:
        all_fp_strong = all(s.confidence == "strong" for s in fp_signals)
        risk_severities = frozenset(s.severity for s in risk_signals)
        only_low_risk = risk_severities.issubset(_FP_DOWNGRADE_MAX_SEVERITY)
        risk_cats = frozenset(s.category for s in risk_signals)
        no_protected_cats = not risk_cats.intersection(_DOWNGRADE_BLOCK_CATEGORIES)

        if all_fp_strong and only_low_risk and no_protected_cats and normalized_base_action == "block":
            final_action = "review"
            downgrade_reason = "strong false-positive signals with only low-severity risk; downgraded block → review"

        elif all_fp_strong and only_low_risk and no_protected_cats and normalized_base_action == "review":
            review_noise_fp_present = any(
                s.signal_id.startswith(("fp:source-search:", "fp:read-only-http-fetch:")) for s in fp_signals
            )
            if review_noise_fp_present and not risk_signals:
                final_action = "warn"
                downgrade_reason = "strong read-only false-positive with no risk signals; downgraded review → warn"

    if upgrade_reason:
        return CompositionResult(
            action=final_action,
            reason=upgrade_reason,
            downgraded=False,
            upgraded=guard_action_severity(final_action) > guard_action_severity(normalized_base_action),
            normalization_reason_code=base_normalization.reason_code,
            original_action=base_normalization.original_action,
        )

    if downgrade_reason:
        return CompositionResult(
            action=final_action,
            reason=downgrade_reason,
            downgraded=True,
            upgraded=False,
            normalization_reason_code=base_normalization.reason_code,
            original_action=base_normalization.original_action,
        )

    if risk_signals:
        top = max(risk_signals, key=lambda signal: SEVERITY_RANK.get(signal.severity, -1))
        return CompositionResult(
            action=final_action,
            reason=f"risk signal '{top.detector}' ({top.severity}/{top.confidence}); base action applies",
            downgraded=False,
            upgraded=False,
            normalization_reason_code=base_normalization.reason_code,
            original_action=base_normalization.original_action,
        )

    return CompositionResult(
        action=final_action,
        reason="advisory false-positive signals only; base action applies",
        downgraded=False,
        upgraded=False,
        normalization_reason_code=base_normalization.reason_code,
        original_action=base_normalization.original_action,
    )
