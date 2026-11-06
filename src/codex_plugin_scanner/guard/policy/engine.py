"""Guard policy evaluation helpers."""

from __future__ import annotations

from collections.abc import Sequence

from ..models import GuardAction
from ..runtime.decisions import GuardDecisionV2, decision_from_legacy_policy_action
from ..runtime.signals import RiskSignalV2


def build_decision_v2(
    policy_action: GuardAction,
    *,
    reason: str,
    signals: Sequence[RiskSignalV2] = (),
) -> GuardDecisionV2:
    return decision_from_legacy_policy_action(policy_action, reason=reason, signals=signals)
