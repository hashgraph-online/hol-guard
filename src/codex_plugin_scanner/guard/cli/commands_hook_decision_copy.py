"""Gather hook copy facts for the existing native decision composition."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ..models import GuardAction
from ..runtime.signals import RiskSignalV2
from .commands_support_runtime_artifacts import _optional_string


def native_hook_decision_copy(
    *,
    composer: Callable[..., dict[str, object]],
    guard_home: Path,
    policy_action: GuardAction,
    decision_signals: Sequence[RiskSignalV2],
    package_evaluation: Any,
    package_policy_action: object,
    has_compound_findings: bool,
    compound_finding_count: object,
    risk_summary: str,
    scanner_raised_to_block: bool,
    has_scanner_evidence: bool,
    scanner_risk_signals: Sequence[str],
    remembered_rule_reason: str | None,
) -> dict[str, object]:
    """Forward gathered fields; Rust builds both decision and display copy."""

    package_copy: dict[str, object] | None = None
    if package_evaluation is not None:
        package_copy = {
            "reason_codes": [
                _optional_string(reason.get("code")) or ""
                for reason in package_evaluation.reasons
                if isinstance(reason, Mapping)
            ],
            "user_title": package_evaluation.user_copy.title,
            "user_summary": package_evaluation.user_copy.summary,
            "user_harness_message": package_evaluation.user_copy.harness_message,
        }
    return composer(
        "decision_build_copy",
        {
            "reason": policy_action,
            "signals": [signal.to_dict() for signal in decision_signals],
            "copy": {
                "policy_action": policy_action,
                "package": package_copy,
                "package_policy_action": package_policy_action,
                "has_compound_findings": has_compound_findings,
                "compound_finding_count": compound_finding_count if has_compound_findings else None,
                "risk_summary": risk_summary,
                "scanner_raised_to_block": scanner_raised_to_block,
                "has_scanner_evidence": has_scanner_evidence,
                "scanner_primary_signal": scanner_risk_signals[0] if scanner_risk_signals else None,
                "base_user_body": None,
                "base_harness_message": None,
                "base_dashboard_primary_detail": None,
                "remembered_rule_reason": remembered_rule_reason,
            },
        },
        guard_home=guard_home,
    )
