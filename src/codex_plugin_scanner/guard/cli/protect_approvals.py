"""Protect approval helpers for package-install flows."""

from __future__ import annotations

import argparse
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..action_lattice import is_guard_action
from ..adapters.base import HarnessContext
from ..approval_hook_copy import authenticated_approval_review_url
from ..approvals import approval_center_hint, attach_primary_approval_link, queue_blocked_approvals
from ..config import load_guard_config
from ..models import GuardAction, GuardArtifact, HarnessDetection
from ..package_execution_context import (
    changed_package_execution_context_components,
    package_execution_context_from_evidence,
    package_execution_context_from_scanner_evidence,
)
from ..policy import build_decision_v2
from ..runtime.decisions import AUTHORITATIVE_DECISION_INCONSISTENT
from ..shim_probe import SHIM_PROBE_ENV_VALUE, SHIM_PROBE_ENV_VAR
from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)
# The response members the native runtime reads to plan the approval.
_PLAN_KEYS = ("request", "receipt", "verdict", "supply_chain_evaluation")


def _queue_local_protect_approvals(
    response_payload: dict[str, object],
    *,
    store: GuardStore,
    guard_home: Path,
    workspace: Path,
    ensure_approval_daemon: Callable[[Path], str],
    approval_delivery_payload: Callable[[str], dict[str, object]],
    localize_pending_approval_copy: Callable[[dict[str, object], str], None],
) -> None:
    if not _should_queue_local_protect_approval():
        return
    plan = _protect_approval_plan(response_payload, guard_home=guard_home)
    if plan is None or plan.get("queue") is not True:
        return
    from ..blocked_request_mode import approval_wait_hint, asks_for_approval, safe_alternative_reason

    try:
        config = load_guard_config(guard_home)
    except (OSError, RuntimeError, TypeError, ValueError):
        config = None
    if config is None or not asks_for_approval(config):
        queued = []
        artifact = _protect_request_artifact(response_payload, workspace=workspace, plan=plan)
        approval_item = (
            _protect_approval_item(response_payload, workspace=workspace, artifact=artifact, plan=plan)
            if artifact is not None
            else None
        )
        if artifact is not None and approval_item is not None:
            from ..approvals import record_unprompted_review

            _annotate_package_execution_context_change(
                approval_item,
                store=store,
                artifact_id=artifact.artifact_id,
            )
            queued = record_unprompted_review(
                detection=HarnessDetection(
                    harness=artifact.harness,
                    installed=True,
                    command_available=True,
                    config_paths=(artifact.config_path,),
                    artifacts=(artifact,),
                ),
                evaluation={"artifacts": [approval_item]},
                store=store,
                redaction_level=config.receipt_redaction_level if config is not None else "full",
            )
        verdict = response_payload.get("verdict")
        reason = verdict.get("reason") if isinstance(verdict, dict) else None
        guidance = safe_alternative_reason(str(reason or "HOL Guard blocked this package request."))
        review_url: str | None = None
        if queued:
            request_id = str(queued[0]["request_id"])
            review_url = _live_request_review_url(request_id, guard_home=guard_home)
            guidance = safe_alternative_reason(
                str(reason or "HOL Guard blocked this package request."),
                reason_code=str(plan["review_reason_code"]),
                approval_queued=True,
            )
            guidance = f"{guidance} {approval_wait_hint(request_id, guard_home=guard_home)}".strip()
            response_payload["approval_resume"] = {
                "request_id": request_id,
                "poll_path": f"/v1/requests/{request_id}",
            }
        response_payload.update(policy_action="block", approval_requests=[], prompted=False, review_hint=guidance)
        evaluation = response_payload.get("supply_chain_evaluation")
        if isinstance(evaluation, dict):
            evaluation["decision"] = "block"
            user_copy = evaluation.get("user_copy")
            evaluation["user_copy"] = {
                **(user_copy if isinstance(user_copy, dict) else {}),
                "harness_message": guidance,
                "next_step": guidance,
                "dashboard_url": review_url,
            }
        return
    artifact = _protect_request_artifact(response_payload, workspace=workspace, plan=plan)
    if artifact is None:
        return
    approval_item = _protect_approval_item(response_payload, workspace=workspace, artifact=artifact, plan=plan)
    if approval_item is None:
        return
    _annotate_package_execution_context_change(approval_item, store=store, artifact_id=artifact.artifact_id)
    try:
        approval_center_url = ensure_approval_daemon(guard_home)
    except RuntimeError:
        response_payload.pop("primary_approval_url", None)
        evaluation = response_payload.get("supply_chain_evaluation")
        if isinstance(evaluation, dict):
            user_copy = evaluation.get("user_copy")
            if not isinstance(user_copy, dict):
                user_copy = {}
                evaluation["user_copy"] = user_copy
            user_copy["dashboard_url"] = None
            user_copy["harness_message"] = "Guard could not create a local approval request. This command has not run."
            user_copy["next_step"] = "Run hol-guard daemon repair\nThen retry this command."
        return
    detection = HarnessDetection(
        harness=artifact.harness,
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )
    queued = queue_blocked_approvals(
        detection=detection,
        evaluation={"artifacts": [approval_item]},
        store=store,
        approval_center_url=approval_center_url,
        redaction_level=config.receipt_redaction_level,
    )
    if not queued:
        return
    response_payload["approval_requests"] = queued
    response_payload["artifact_id"] = artifact.artifact_id
    response_payload["approval_request_ids"] = [
        str(item["request_id"]) for item in queued if isinstance(item, dict) and "request_id" in item
    ]
    response_payload["approval_center_url"] = approval_center_url
    harness = artifact.harness
    display_harness = str(plan["display_harness"])
    attach_primary_approval_link(
        response_payload,
        harness=harness,
        approval_center_url=approval_center_url,
    )
    response_payload["review_hint"] = approval_center_hint(
        context=HarnessContext(home_dir=guard_home, workspace_dir=workspace, guard_home=guard_home),
        harness=display_harness,
        approval_center_url=approval_center_url,
        queued=queued,
        request_id=_optional_string(response_payload.get("primary_approval_request_id")),
        artifact_id=artifact.artifact_id,
    )
    response_payload["approval_delivery"] = approval_delivery_payload(display_harness)
    localize_pending_approval_copy(response_payload, display_harness)
    _bind_protect_receipt_approval(response_payload, store=store)


def _should_queue_local_protect_approval() -> bool:
    if os.environ.get(SHIM_PROBE_ENV_VAR) == SHIM_PROBE_ENV_VALUE:
        return False
    return not (
        os.environ.get("PYTEST_CURRENT_TEST") and os.environ.get("HOL_GUARD_TEST_SKIP_LOCAL_APPROVAL_QUEUE") == "1"
    )


def _protect_approval_plan(
    response_payload: dict[str, object],
    *,
    guard_home: Path | None = None,
) -> dict[str, Any] | None:
    """Ask the native runtime what this protect response queues for approval.

    Without the runtime nothing is queued, and the response keeps the verdict
    the native protect request gave it.
    """
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        plan = native_runner_authority(
            "protect_approval_plan",
            {key: response_payload.get(key) for key in _PLAN_KEYS},
            guard_home=guard_home,
        )
    except NativeRunnerAuthorityError as error:
        _LOGGER.debug("protect approval plan unavailable: %s", error)
        return None
    return plan if isinstance(plan, dict) else None


def _protect_request_artifact(
    response_payload: dict[str, object],
    *,
    workspace: Path,
    plan: dict[str, Any] | None = None,
) -> GuardArtifact | None:
    plan = plan if plan is not None else _protect_approval_plan(response_payload)
    fields = plan.get("artifact") if plan is not None else None
    request = response_payload.get("request")
    if plan is None or not isinstance(fields, dict) or not isinstance(request, dict):
        return None
    command = fields.get("redacted_command")
    redacted_command = command if isinstance(command, str) else None
    return GuardArtifact(
        artifact_id=str(fields["artifact_id"]),
        name=str(fields["name"]),
        harness=str(plan["harness"]),
        artifact_type="package_request",
        source_scope=str(fields["source_scope"]),
        config_path=str(workspace / "hol-guard.toml"),
        command=redacted_command,
        metadata={
            "package_manager": fields["package_manager"],
            "intent_kind": fields["intent_kind"],
            "targets": request.get("targets") if isinstance(request.get("targets"), list) else [],
            "manifest_paths": request.get("manifest_paths") if isinstance(request.get("manifest_paths"), list) else [],
            "lockfile_paths": request.get("lockfile_paths") if isinstance(request.get("lockfile_paths"), list) else [],
            "redacted_command": redacted_command,
        },
    )


def _protect_approval_item(
    response_payload: dict[str, object],
    *,
    workspace: Path,
    artifact: GuardArtifact,
    plan: dict[str, Any] | None = None,
) -> dict[str, object] | None:
    del workspace
    plan = plan if plan is not None else _protect_approval_plan(response_payload)
    fields = plan.get("item") if plan is not None else None
    policy_action = plan.get("policy_action") if plan is not None else None
    if not isinstance(fields, dict) or not is_guard_action(policy_action):
        return None
    request = response_payload.get("request")
    package_context = request.get("package_execution_context") if isinstance(request, dict) else None
    scanner_evidence = [dict(package_context)] if isinstance(package_context, dict) else []
    if fields["actions_disagree"] is True:
        scanner_evidence.append(
            {
                "source": "decision_contract",
                "reason_code": AUTHORITATIVE_DECISION_INCONSISTENT,
                "final_action": policy_action,
            }
        )
    decision_v2_payload = build_decision_v2(policy_action, reason=str(fields["decision_reason"])).to_dict()
    if isinstance(fields["cloud_reason_code"], str):
        decision_v2_payload["package_review_cloud_reason_code"] = fields["cloud_reason_code"]
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_name": artifact.name,
        "artifact_hash": fields["artifact_hash"] or artifact.artifact_id,
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "policy_action": policy_action,
        "changed_fields": fields["changed_fields"],
        "risk_summary": fields["risk_summary"],
        "risk_signals": fields["risk_signals"],
        "action_envelope_json": _protect_approval_action_envelope(
            response_payload, fields["envelope"], policy_action=policy_action
        ),
        "decision_v2_json": decision_v2_payload,
        "scanner_evidence": scanner_evidence,
    }


def _protect_approval_action_envelope(
    response_payload: dict[str, object],
    edits: object,
    *,
    policy_action: GuardAction,
) -> dict[str, object] | None:
    """The receipt's action envelope with the native runtime's edits applied, in its own key order."""

    receipt = response_payload.get("receipt")
    value = receipt.get("action_envelope_json") if isinstance(receipt, dict) else None
    if not isinstance(value, dict) or not isinstance(edits, dict):
        return None
    envelope = dict(value)
    for key in edits["drop"]:
        envelope.pop(key, None)
    for key in edits["set"]:
        envelope[key] = policy_action
    return envelope


def _annotate_package_execution_context_change(
    approval_item: dict[str, object],
    *,
    store: GuardStore,
    artifact_id: str,
) -> None:
    scanner_evidence = approval_item.get("scanner_evidence")
    current = package_execution_context_from_scanner_evidence(scanner_evidence)
    if current is None:
        return
    previous = None
    for request in store.list_approval_requests(status="resolved", limit=200):
        if request.get("artifact_id") != artifact_id:
            continue
        previous = package_execution_context_from_scanner_evidence(request.get("scanner_evidence"))
        if previous is not None:
            break
    if previous is None or previous.digest == current.digest:
        return
    changed_components = changed_package_execution_context_components(previous, current)
    if not changed_components:
        return
    changed_fields = _string_list(approval_item.get("changed_fields"))
    changed_fields.extend(f"package_context_{component}" for component in changed_components)
    approval_item["changed_fields"] = list(dict.fromkeys(changed_fields))
    if not isinstance(scanner_evidence, list):
        return
    for index, evidence in enumerate(scanner_evidence):
        parsed = package_execution_context_from_evidence(evidence)
        if parsed is not None and parsed.digest == current.digest and isinstance(evidence, dict):
            scanner_evidence[index] = {**evidence, "changed_components": list(changed_components)}
            break


def _bind_protect_receipt_approval(response_payload: dict[str, object], *, store: GuardStore) -> None:
    receipt = response_payload.get("receipt")
    if not isinstance(receipt, dict):
        return
    receipt_id = _optional_string(receipt.get("receipt_id"))
    approval_request_id = _optional_string(response_payload.get("primary_approval_request_id"))
    queued_ids = response_payload.get("approval_request_ids")
    if approval_request_id is None and isinstance(queued_ids, list) and len(queued_ids) == 1:
        # This block queued exactly one request, so the receipt binds to it
        # even when the display link could not be resolved.
        approval_request_id = _optional_string(queued_ids[0])
    if receipt_id is None or approval_request_id is None:
        return
    receipt["approval_source"] = "approval-center"
    receipt["approval_request_id"] = approval_request_id
    store.update_receipt_approval_context(
        receipt_id,
        approval_source="approval-center",
        approval_request_id=approval_request_id,
    )


def _suppress_package_shim_allow_output(args: argparse.Namespace, response_payload: dict[str, object]) -> bool:
    if not bool(getattr(args, "package_shim_ui", False)) or bool(getattr(args, "json", False)):
        return False
    verdict = response_payload.get("verdict")
    action = _optional_string(verdict.get("action")) if isinstance(verdict, dict) else None
    return action in {"allow", "warn"}


def _live_request_review_url(request_id: str, *, guard_home: Path) -> str | None:
    """Link to the queued request on the running daemon, or None.

    The stored request URL uses the configured port, which is wrong when the
    daemon fell back to another one, so the link comes from the verified live
    daemon. This never starts a daemon. Human output signs the loopback link;
    without a running daemon or its token there is nothing to open, and the
    guidance keeps the wait command alone.
    """

    from ..daemon.manager import load_guard_daemon_url

    try:
        daemon_url = load_guard_daemon_url(guard_home)
    except (OSError, RuntimeError, ValueError):
        # The request is already queued; a failed optional lookup (including
        # NativeDaemonLifecycleError) must not replace the denial and wait guidance.
        return None
    if daemon_url is None:
        return None
    review_url = f"{daemon_url.rstrip('/')}/requests/{request_id}"
    if authenticated_approval_review_url(review_url, guard_home=guard_home) is None:
        return None
    return review_url


def _optional_string(value: object | None) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _string_list(value: object | None) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]
