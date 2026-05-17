"""Signal composition rules for Guard detector action decisions.

Combines false-positive advisory signals with risk signals to produce a
calibrated action recommendation: allow, warn, ask, or block.

The base policy action (from config/approval policy) is used as the starting
point. Composition rules may only *downgrade* (block → ask, ask → warn,
warn → allow) when strong false-positive evidence is present, and may only
*upgrade* (warn → ask, ask → block) when high-confidence risk signals demand it.

Composition rules never override an explicit user policy choice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from codex_plugin_scanner.guard.runtime.signals import RiskSignalV2

ComposedAction = Literal["allow", "warn", "ask", "block"]

_ACTION_RANK: dict[ComposedAction, int] = {
    "allow": 0,
    "warn": 1,
    "ask": 2,
    "block": 3,
}

_RANK_ACTION: dict[int, ComposedAction] = {v: k for k, v in _ACTION_RANK.items()}

_DOWNGRADE_BLOCK_CATEGORIES = frozenset({"bypass", "persistence"})
_DOWNGRADE_PROTECTED_SEVERITIES = frozenset({"critical", "high"})
_FP_DOWNGRADE_MAX_SEVERITY = frozenset({"info", "low"})


@dataclass(frozen=True, slots=True)
class CompositionResult:
    """Result of applying composition rules to a set of signals."""

    action: ComposedAction
    reason: str
    downgraded: bool
    upgraded: bool


def compose_action_from_signals(
    signals: tuple[RiskSignalV2, ...],
    base_action: ComposedAction,
) -> CompositionResult:
    """Apply composition rules to signals and return a calibrated action.

    Args:
        signals: All signals from the detector run (risk + advisory).
        base_action: The starting action from config/policy evaluation.

    Returns:
        A ``CompositionResult`` with the final action and an explanation.
    """
    risk_signals = tuple(s for s in signals if s.category != "false_positive")
    fp_signals = tuple(s for s in signals if s.category == "false_positive")

    if not signals:
        return CompositionResult(
            action=base_action,
            reason="no detector signals; base policy action applies",
            downgraded=False,
            upgraded=False,
        )

    current_rank = _ACTION_RANK[base_action]
    upgrade_reason: str | None = None
    downgrade_reason: str | None = None

    for signal in risk_signals:
        if signal.category == "bypass" and signal.confidence in ("likely", "strong"):
            new_rank = max(current_rank, _ACTION_RANK["block"])
            if new_rank > current_rank:
                upgrade_reason = f"bypass signal '{signal.detector}' forces block"
                current_rank = new_rank

        if signal.category == "persistence" and signal.severity in ("high", "critical"):
            new_rank = max(current_rank, _ACTION_RANK["ask"])
            if new_rank > current_rank:
                upgrade_reason = upgrade_reason or f"persistence signal '{signal.detector}' requires review"
                current_rank = new_rank

        if signal.severity == "critical" and signal.confidence in ("likely", "strong"):
            new_rank = max(current_rank, _ACTION_RANK["block"])
            if new_rank > current_rank:
                upgrade_reason = upgrade_reason or f"critical signal '{signal.detector}' forces block"
                current_rank = new_rank

    final_rank = current_rank

    if fp_signals and not upgrade_reason:
        all_fp_strong = all(s.confidence == "strong" for s in fp_signals)
        risk_severities = frozenset(s.severity for s in risk_signals)
        only_low_risk = risk_severities.issubset(_FP_DOWNGRADE_MAX_SEVERITY)
        risk_cats = frozenset(s.category for s in risk_signals)
        no_protected_cats = not risk_cats.intersection(_DOWNGRADE_BLOCK_CATEGORIES)

        if all_fp_strong and only_low_risk and no_protected_cats and base_action == "block":
            final_rank = min(final_rank, _ACTION_RANK["ask"])
            downgrade_reason = "strong false-positive signals with only low-severity risk; downgraded block → ask"

        elif all_fp_strong and only_low_risk and no_protected_cats and base_action == "ask":
            review_noise_fp_present = any(
                s.signal_id.startswith(("fp:source-search:", "fp:read-only-http-fetch:")) for s in fp_signals
            )
            if review_noise_fp_present and not risk_signals:
                final_rank = min(final_rank, _ACTION_RANK["warn"])
                downgrade_reason = "strong read-only false-positive with no risk signals; downgraded ask → warn"

    if upgrade_reason:
        return CompositionResult(
            action=_RANK_ACTION[final_rank],
            reason=upgrade_reason,
            downgraded=False,
            upgraded=final_rank > _ACTION_RANK[base_action],
        )

    if downgrade_reason:
        return CompositionResult(
            action=_RANK_ACTION[final_rank],
            reason=downgrade_reason,
            downgraded=True,
            upgraded=False,
        )

    if risk_signals:
        top = max(risk_signals, key=lambda s: (_ACTION_RANK.get("ask", 2), s.severity))
        return CompositionResult(
            action=_RANK_ACTION[final_rank],
            reason=f"risk signal '{top.detector}' ({top.severity}/{top.confidence}); base action applies",
            downgraded=False,
            upgraded=False,
        )

    return CompositionResult(
        action=_RANK_ACTION[final_rank],
        reason="advisory false-positive signals only; base action applies",
        downgraded=False,
        upgraded=False,
    )
