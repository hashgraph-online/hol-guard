"""Package evaluation result finalization through the live evaluator."""

from __future__ import annotations


def _finalize_evaluation(
    draft: _eval._EvaluationDraft,
    *,
    package_intent_hash: str,
    workspace_fingerprint: str | None,
) -> _eval.PackageRequestEvaluation:
    packages = tuple(_eval._with_support_metadata(item) for item in draft.packages)
    primary_package = packages[0] if packages else {}
    package_display = _eval._package_display_name(primary_package)
    requested_version = _eval._optional_string(primary_package.get("requestedVersion")) or _eval._optional_string(
        primary_package.get("resolvedVersion")
    )
    package_ref = f"{package_display}@{requested_version}" if requested_version else package_display
    prefix = {
        "block": "HOL Guard blocked",
        "ask": "HOL Guard paused",
        "warn": "HOL Guard found risk signals for",
    }.get(draft.decision, "HOL Guard recorded")
    risk_summary = {
        "block": f"{prefix} `{package_ref}` before install.",
        "ask": f"{prefix} `{package_ref}` for review before install.",
        "warn": f"{prefix} `{package_ref}` before install.",
        "monitor": f"{prefix} `{package_ref}` for continued monitoring.",
        "allow": f"{prefix} `{package_ref}` as trusted by policy.",
    }[draft.decision]
    reason_message = _eval._optional_string(draft.reasons[0].get("message")) if draft.reasons else None
    reason_code = _eval._optional_string(draft.reasons[0].get("code")) if draft.reasons else None
    policy_action: _eval.GuardAction = (
        "review"
        if draft.decision == "ask" and reason_code == "external_tarball_source"
        else _eval._DECISION_TO_GUARD_ACTION[draft.decision]
    )
    source_risk_summaries = {
        "insecure_source_url": "from insecure HTTP source before install.",
        "external_tarball_source": "from external tarball source before install.",
        "git_dependency_source": "from git dependency source before install.",
    }
    if reason_code in source_risk_summaries and reason_message is not None:
        risk_summary = f"{prefix} `{package_ref}` {source_risk_summaries[reason_code]}"
    fix_command = _eval._fix_command(primary_package)
    title = {
        "block": "Critical install blocked",
        "ask": "Review required",
        "warn": "Proceed with caution",
        "monitor": "Monitoring this package",
        "allow": "Allowed by policy",
    }[draft.decision]
    summary = (
        reason_message
        or {
            "block": f"{package_display} needs a safer version before you continue.",
            "ask": f"{package_display} needs a human review before Guard allows it.",
            "warn": f"Guard found risk signals for {package_display}. Proceed with caution.",
            "monitor": "Guard recorded the package intent and will keep watching for new intelligence.",
            "allow": "Guard matched a scoped allow rule for this package request.",
        }[draft.decision]
    )
    if len(draft.packages) > 1:
        others = ", ".join(_eval._package_display_name(item) for item in draft.packages[1:3])
        if others:
            summary = f"{summary} Also flagged: {others}."
    harness_parts = [risk_summary]
    if reason_message:
        harness_parts.append(f"Reason: {_eval._ensure_terminal_punctuation(reason_message)}")
    if fix_command:
        harness_parts.append(f"Fix: install `{fix_command}` or choose a team exception.")
    user_copy = _eval._normalize_package_user_copy(
        _eval.SupplyChainUserCopy(
            title=title,
            summary=summary,
            next_step=fix_command,
            dashboard_url=None,
            harness_message=" ".join(part.strip() for part in harness_parts if part.strip()),
        ),
        policy_action=policy_action,
    )
    return _eval.PackageRequestEvaluation(
        decision=draft.decision,
        policy_action=policy_action,
        enforcement=draft.enforcement,
        entitlement_state=draft.entitlement_state,
        cache_status=draft.cache_status,
        package_intent_hash=package_intent_hash,
        policy_version=draft.policy_version,
        bundle_version=draft.bundle_version,
        workspace_fingerprint=workspace_fingerprint,
        reasons=draft.reasons,
        packages=packages,
        risk_summary=risk_summary,
        user_copy=user_copy,
        matched_rule_id=draft.matched_rule_id,
        exception_id=draft.exception_id,
        refresh_required=draft.refresh_required,
        record_monitor_evidence=draft.record_monitor_evidence,
        evidence_ids=tuple(
            _eval._evidence_id(package_intent_hash, item)
            for item in draft.packages
            if _eval._should_record_package(item, draft.decision)
        ),
        external_archive_downloads=draft.external_archive_downloads,
        external_archive_source_hashes=draft.external_archive_source_hashes,
    )


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
