"""Rebuild package presentation after current policy changes its outcome."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from ..models import GuardAction
from .package_user_copy import SupplyChainUserCopy

if TYPE_CHECKING:
    from .supply_chain_package_eval import PackageRequestEvaluation


def _package_evaluation_with_current_policy_action(
    evaluation: PackageRequestEvaluation,
    *,
    current_action: GuardAction,
) -> PackageRequestEvaluation:
    """Apply current package policy before consulting remembered user state."""

    if current_action == evaluation.policy_action:
        return evaluation
    decision = _package_decision_for_action(current_action)
    rewritten_packages = tuple({**package, "decision": decision} for package in evaluation.packages)
    action_label = {
        "block": "blocks",
        "sandbox-required": "requires sandbox enforcement for",
        "require-reapproval": "requires fresh approval for",
        "review": "requires review for",
        "warn": "warns about",
        "allow": "allows",
    }[current_action]
    package_label = "this package request"
    package_label_entries = getattr(evaluation, "packages", ())
    if (
        isinstance(package_label_entries, tuple)
        and package_label_entries
        and isinstance(package_label_entries[0], dict)
    ):
        primary_package = package_label_entries[0]
        package_name = primary_package.get("name")
        package_version = primary_package.get("requestedVersion") or primary_package.get("resolvedVersion")
        if isinstance(package_name, str) and package_name:
            package_ref = (
                f"{package_name}@{package_version}"
                if isinstance(package_version, str) and package_version
                else package_name
            )
            package_label = f"`{package_ref}`"
    summary = f"HOL Guard's current package policy {action_label} {package_label}."
    reason = {
        "code": "current_package_policy",
        "message": summary,
        "severity": "high" if current_action in {"block", "sandbox-required"} else "medium",
        "source": "guard-local",
        "policy_action": current_action,
    }
    needs_review = current_action in {"review", "require-reapproval", "sandbox-required", "block"}
    return replace(
        evaluation,
        decision=decision,
        policy_action=current_action,
        reasons=(reason, *tuple(item for item in evaluation.reasons if item.get("code") != reason["code"])),
        policy_rule_identity=None,
        packages=rewritten_packages,
        risk_summary=summary,
        user_copy=SupplyChainUserCopy(
            title="Current package policy",
            summary=summary,
            next_step="Review the current package request in HOL Guard, then retry." if needs_review else None,
            dashboard_url=None,
            harness_message=summary,
        ),
        record_monitor_evidence=False,
    )


def _package_decision_for_action(action: GuardAction) -> str:
    if action == "block":
        return "block"
    if action in {"review", "require-reapproval", "sandbox-required"}:
        return "ask"
    if action == "warn":
        return "warn"
    return "allow"
