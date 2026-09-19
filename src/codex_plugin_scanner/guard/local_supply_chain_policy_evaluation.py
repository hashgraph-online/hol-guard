"""Policy evaluation helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _package_evaluation_with_current_policy_action(
    evaluation: _api.Any,
    *,
    current_action: _api.GuardAction,
) -> _api.Any:
    """Apply current package policy before consulting remembered user state."""

    if current_action == evaluation.policy_action:
        return evaluation
    decision = _api._package_decision_for_action(current_action)
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
    return _api.replace(
        evaluation,
        decision=decision,
        policy_action=current_action,
        reasons=(reason, *tuple(item for item in evaluation.reasons if item.get("code") != reason["code"])),
        packages=rewritten_packages,
        risk_summary=summary,
        user_copy=_api._supply_chain_package_eval_module().SupplyChainUserCopy(
            title="Current package policy",
            summary=summary,
            next_step="Review the current package request in HOL Guard, then retry." if needs_review else None,
            dashboard_url=None,
            harness_message=summary,
        ),
        record_monitor_evidence=False,
    )


def _package_evaluation_with_rejected_reuse(
    evaluation: _api.Any,
    reuse: _api.ApprovalReuseDecision,
) -> _api.Any:
    """Retain current package evidence while recording rejected saved state."""

    reason = {
        "code": reuse.reason_code,
        "message": _api._approval_reuse_reason_message(reuse),
        "severity": "high" if reuse.status == "rejected" else "low",
        "source": "guard-local",
        "approval_reuse": reuse.to_evidence(),
    }
    reasons = (reason, *tuple(item for item in evaluation.reasons if item.get("code") != reuse.reason_code))
    if reuse.action == evaluation.policy_action:
        return _api.replace(evaluation, reasons=reasons)
    decision = _api._package_decision_for_action(reuse.action)
    packages = tuple({**package, "decision": decision} for package in evaluation.packages)
    summary = _api._approval_reuse_reason_message(reuse)
    return _api.replace(
        evaluation,
        decision=decision,
        policy_action=reuse.action,
        reasons=reasons,
        packages=packages,
        risk_summary=summary,
        user_copy=_api._supply_chain_package_eval_module().SupplyChainUserCopy(
            title="Saved approval not reusable",
            summary=summary,
            next_step="Review the current package request in HOL Guard, then retry.",
            dashboard_url=None,
            harness_message=summary,
        ),
        record_monitor_evidence=False,
    )


def _approval_reuse_reason_message(reuse: _api.ApprovalReuseDecision) -> str:
    messages = {
        "approval_reuse_current_block": (
            "Saved approval was rejected because current package policy blocks this request."
        ),
        "approval_reuse_sandbox_required": (
            "Saved approval was rejected because current package policy requires sandbox enforcement."
        ),
        "approval_reuse_reapproval_required": (
            "Saved approval was rejected because current package policy requires fresh approval."
        ),
        "approval_reuse_integrity_failure": (
            "Saved approval was rejected because its integrity could not be verified."
        ),
        "approval_reuse_identity_changed": (
            "Saved approval was rejected because the current package identity or scope changed."
        ),
        "approval_reuse_content_changed": (
            "Saved approval was rejected because the current package content or execution context changed."
        ),
        "approval_reuse_claim_failed": (
            "Saved approval was rejected because it changed, expired, or was already consumed."
        ),
        "approval_reuse_context_changed_after_claim": (
            "Saved approval was rejected because retained authority changed after it was claimed."
        ),
        "approval_reuse_saved_action_unknown": (
            "Saved approval was rejected because its action is unknown or malformed."
        ),
    }
    return messages.get(
        reuse.reason_code,
        f"Saved package policy was not reused ({reuse.reason_code}).",
    )


def _package_decision_for_action(action: _api.GuardAction) -> str:
    if action == "block":
        return "block"
    if action in {"review", "require-reapproval", "sandbox-required"}:
        return "ask"
    if action == "warn":
        return "warn"
    return "allow"


def _package_policy_workspace_candidates(
    *,
    artifact: _api.GuardArtifact,
    artifact_hash: str,
    workspace_dir: _api.Path,
    execution_context: _api.PackageExecutionContext | None = None,
) -> tuple[str, ...]:
    resolved_execution_context = execution_context or _api.build_package_execution_context(
        workspace_dir=workspace_dir,
        artifact=artifact,
    )
    runtime_workspace = _api.package_request_runtime_workspace_scope(
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact_hash,
        artifact_type=artifact.artifact_type,
        execution_context=resolved_execution_context,
    )
    return (runtime_workspace,) if runtime_workspace is not None else ()


def _stored_package_policy_is_stale_policy_bundle_family(decision: dict[str, object], *, store: _api.Any) -> bool:
    """Ignore package family rows only when the current bundle proves they are stale."""

    if not (
        _api._string_value(decision.get("source")) == "policy-bundle"
        and _api._string_value(decision.get("artifact_id")) == "family:package-request"
        and decision.get("artifact_hash") is None
        and _api._string_value(decision.get("scope")) in {"harness", "global"}
    ):
        return False
    owner = _api._string_value(decision.get("owner"))
    if owner is None:
        return False
    get_sync_payload = getattr(store, "get_sync_payload", None)
    if not callable(get_sync_payload):
        return False
    from .synced_policy import validated_synced_policy_bundle

    bundle = validated_synced_policy_bundle(store)
    if bundle is None:
        return False
    rules = bundle.get("rules")
    if not isinstance(rules, list):
        return False
    matching_rules = [
        rule for rule in rules if isinstance(rule, dict) and _api._string_value(rule.get("ruleId")) == owner
    ]
    if not matching_rules:
        return True
    from .policy_bundle_decisions import policy_bundle_rule_saved_decision_families

    return not any("package-request" in policy_bundle_rule_saved_decision_families(rule) for rule in matching_rules)


def _stored_package_policy_evaluation_requires_review(evaluation: _api.Any) -> bool:
    policy_action = _api._string_value(getattr(evaluation, "policy_action", None))
    decision = _api._string_value(getattr(evaluation, "decision", None))
    return policy_action in {"block", "require-reapproval"} or decision in {"block", "ask"}


def _saved_package_policy_clear_command(
    *,
    artifact: _api.GuardArtifact,
    artifact_hash: str,
    matched_policy: dict[str, object],
    workspace_dir: _api.Path,
) -> str:
    scope = _api._string_value(matched_policy.get("scope")) or "artifact"
    command = [
        "hol-guard",
        "policies",
        "clear",
    ]
    decision_id = matched_policy.get("decision_id")
    if isinstance(decision_id, int):
        command.extend(("--decision-id", str(decision_id)))
    command.extend(
        ("--harness", _api._string_value(matched_policy.get("harness")) or artifact.harness, "--scope", scope)
    )
    artifact_id = _api._string_value(matched_policy.get("artifact_id"))
    if artifact_id is None and scope in {"artifact", "workspace", "harness", "global"}:
        artifact_id = artifact.artifact_id
    if artifact_id is not None:
        command.extend(("--artifact-id", artifact_id))
    matched_hash = _api._string_value(matched_policy.get("artifact_hash"))
    if matched_hash is not None:
        command.extend(("--artifact-hash", matched_hash))
    policy_workspace = _api._string_value(matched_policy.get("workspace"))
    if policy_workspace is None and scope in {"artifact", "workspace"}:
        policy_workspace = str(workspace_dir)
    if policy_workspace is not None:
        command.extend(("--policy-workspace", policy_workspace))
    publisher = _api._string_value(matched_policy.get("publisher"))
    if publisher is not None:
        command.extend(("--publisher", publisher))
    return _api.shlex.join(command)


def _evaluation_uses_saved_package_approval(evaluation: _api.Any) -> bool:
    return any(reason.get("code") == "saved_package_approval" for reason in evaluation.reasons)


def _package_approval_reuse_evidence(evaluation: _api.Any) -> tuple[dict[str, object], ...]:
    evidence_items: list[dict[str, object]] = []
    for reason in evaluation.reasons:
        reuse_evidence = reason.get("approval_reuse")
        if not isinstance(reuse_evidence, dict):
            continue
        evidence: dict[str, object] = {"source": "approval_reuse"}
        evidence.update({str(key): value for key, value in reuse_evidence.items()})
        evidence_items.append(evidence)
    return tuple(evidence_items)


def _package_policy_override_evaluation(
    evaluation: _api.Any,
    *,
    decision: str,
    policy_action: str,
    title: str,
    summary: str,
    harness_message: str,
    next_step: str | None = None,
    reason_code: str,
    reason_message: str,
    approval_reuse: _api.ApprovalReuseDecision | None = None,
    approval_claim_disposition: _api._PackageApprovalClaimDisposition | None = None,
) -> _api.Any:
    reason: dict[str, object] = {
        "code": reason_code,
        "message": reason_message,
        "severity": "low",
        "source": "guard-local",
    }
    if approval_reuse is not None:
        reason["approval_reuse"] = approval_reuse.to_evidence()
    if approval_claim_disposition is not None:
        reason["approval_claim_disposition"] = approval_claim_disposition
    packages = tuple({**package, "decision": decision} for package in evaluation.packages)
    return _api.replace(
        evaluation,
        decision=decision,
        policy_action=policy_action,
        reasons=(reason, *tuple(item for item in evaluation.reasons if item != reason)),
        packages=packages,
        risk_summary=harness_message,
        user_copy=_api._supply_chain_package_eval_module().SupplyChainUserCopy(
            title=title,
            summary=summary,
            next_step=next_step,
            dashboard_url=None,
            harness_message=harness_message,
        ),
        record_monitor_evidence=False,
    )


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
