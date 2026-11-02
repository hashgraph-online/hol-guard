"""Approval queue orchestration for local Guard reviews."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.metadata
import logging
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, ParamSpec, TypeGuard, TypeVar, cast
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..version import __version__
from .action_lattice import normalize_guard_action_result
from .adapters import get_adapter
from .adapters.base import HarnessContext
from .approval_gate import ApprovalGateGrant, ApprovalGateInput, require_approval_decision
from .approval_once_eligibility import requires_local_once_approval
from .approval_resolution import require_resolvable_approval_request
from .approval_scope_selection import resolve_request_scope_selection
from .approval_scope_support import (
    RETRY_CANNOT_REUSE_APPROVAL,
    apply_scope_surfaces,
    package_request_portable_workspace_scope,
    resolve_request_workspace_scope,
    scope_payload_for_request,
)
from .cli.connect_flow import (
    connect_retry_refresh_race_from_state,
    connect_retry_required_from_state,
    resolve_guard_cloud_state,
)
from .config import load_guard_config, maybe_auto_revert_watch
from .consumer.projection import wire_artifact
from .continuation_payload import parse_aware_timestamp
from .continuation_runtime import continuation_offer_facts
from .daemon.manager import load_guard_daemon_auth_token
from .desktop_notifications import (
    DesktopApprovalNotification,
    notify_pending_approval_once,
)
from .harness_posture import harness_posture_summary
from .local_dashboard_session import (
    build_approval_browser_url as build_approval_browser_url,
)
from .local_dashboard_session import (
    build_local_dashboard_session_token,
)
from .local_supply_chain import build_local_supply_chain_posture
from .managed_install_proof import verify_managed_install_proof
from .memory_decision_outbox import enqueue_memory_decision_event
from .models import (
    GuardArtifact,
    HarnessDetection,
    PolicyDecision,
)
from .native_approval_resolution import (
    INTEGRITY_UNAVAILABLE,
    ApprovalResolutionPlanUnavailableError,
    native_approval_resolution_plan,
)
from .native_approval_scope import UNAVAILABLE as APPROVAL_SCOPE_UNAVAILABLE
from .native_approval_scope import ApprovalScopeUnavailableError
from .native_package_workspace_scope import NativePackageWorkspaceScopeError
from .native_protection_health import NativeProtectionHealthError
from .package_execution_context import package_execution_context_from_scanner_evidence
from .protection_capabilities import protection_capability_payloads
from .risk import artifact_risk_profile
from .runtime.command_capability import command_capability_status
from .runtime.github_workflow_runtime import (
    issue_github_workflow_capability_for_resolution,
)
from .runtime.protection_health_runtime import build_runtime_protection_health
from .store import (
    GuardStore,
)
from .synced_policy import synced_policy_bundle_validation
from .temporary_mcp_approvals import (
    TemporaryMcpGrantSelection,
    parse_temporary_mcp_grant_selection,
    temporary_mcp_grant_decision,
)
from .trusted_local_tools import (
    LocalToolGrantSelection,
    local_tool_grant_decision,
    parse_local_tool_grant_selection,
)
from .value_coercion import coerce_non_negative_int

_LOGGER = logging.getLogger(__name__)
_EVENT_SUMMARY_FIELDS = ("status", "sync_skipped", "sync_reason", "next_retry_after")
_GUARD_URL_FIELDS = ("dashboard_url", "inbox_url", "fleet_url", "connect_url")
_CLOUD_STATUS_UNAVAILABLE = "HOL Guard could not load the Guard Cloud status from its native runtime."
_HEADLINE_UNAVAILABLE = {
    "headline_state": "degraded",
    "headline_label": "Degraded",
    "headline_detail": "HOL Guard could not load the protection headline from its native runtime.",
}
# The two headlines that need no protection report keep their copy when the
# native runtime is out, so an offline runtime or a waiting decision is never
# hidden behind the degraded fallback.
_HEADLINE_SETUP = {
    "headline_state": "setup",
    "headline_label": "Setup required",
    "headline_detail": "The local Guard runtime is offline. Start the daemon or rerun hol-guard bootstrap.",
}
_HEADLINE_NEEDS_DECISION = {
    "headline_state": "needs_decision",
    "headline_label": "Decision needed",
    "headline_detail": "One or more actions are waiting for a decision in the current review queue.",
}
# Artifact metadata the resident reads for a queued request.
_QUEUE_METADATA_KEYS = ("raw_command_text", "command_text", "command_rule_matches", "extension_allow_hint")

GUARD_COMMAND = "hol-guard"
GUARD_DASHBOARD_URL = "https://hol.org/guard"
GUARD_INBOX_URL = f"{GUARD_DASHBOARD_URL}/inbox"
GUARD_FLEET_URL = f"{GUARD_DASHBOARD_URL}/protect"
GUARD_CONNECT_URL = f"{GUARD_DASHBOARD_URL}/connect"
_APPROVAL_RESOLUTION_LOCKS = tuple(threading.RLock() for _ in range(64))
_P = ParamSpec("_P")
_R = TypeVar("_R")


def _current_guard_version() -> str:
    try:
        return importlib.metadata.version("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        return __version__


class ApprovalRequestNotFoundError(ValueError):
    """Raised when an approval request ID does not exist."""


def _serialize_approval_resolution(function: Callable[_P, _R]) -> Callable[_P, _R]:
    @wraps(function)
    def serialized(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        request_id = kwargs.get("request_id")
        if not isinstance(request_id, str):
            raise TypeError("request_id must be provided as a string keyword argument")
        digest = hashlib.sha256(request_id.encode("utf-8")).digest()
        lock = _APPROVAL_RESOLUTION_LOCKS[int.from_bytes(digest[:2], "big") % len(_APPROVAL_RESOLUTION_LOCKS)]
        with lock:
            return function(*args, **kwargs)

    return serialized


class ApprovalRequestAlreadyResolvedError(ValueError):
    """Raised when an approval request was already resolved."""


_LINK_FIELDS = ("request_id", "artifact_id", "approval_url")


def _link_item(item: object) -> dict[str, str] | None:
    if not isinstance(item, Mapping):
        return None
    fields = {key: value for key in _LINK_FIELDS if isinstance(value := item.get(key), str)}
    return {**fields, "harness": str(item.get("harness") or "")}


def _text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _approval_link(mode: str, queued: Sequence[object] | None, **fields: object) -> dict[str, object]:
    """Ask the native runtime which queued request and review link a block binds to.

    The link is display only, so an unavailable runtime yields no link.
    """
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    items = None if queued is None else [_link_item(item) for item in queued]
    try:
        return native_runner_authority("approval_link", {"mode": mode, "queued": items, **fields})
    except NativeRunnerAuthorityError:
        return {}


def primary_approval_request(
    queued: Sequence[object],
    *,
    harness: str | None = None,
    request_id: str | None = None,
    artifact_id: str | None = None,
) -> dict[str, object] | None:
    """Return the approval request created for this blocked action."""

    fields = {"harness": _text(harness), "request_id": _text(request_id), "artifact_id": _text(artifact_id)}
    index = _approval_link("primary", queued, **fields).get("index")
    item = queued[index] if isinstance(index, int) and 0 <= index < len(queued) else None
    return dict(item) if isinstance(item, Mapping) else None


def primary_approval_url(
    queued: Sequence[object],
    *,
    harness: str | None = None,
    approval_center_url: str | None = None,
    request_id: str | None = None,
    artifact_id: str | None = None,
) -> str | None:
    fields = {"harness": _text(harness), "request_id": _text(request_id), "artifact_id": _text(artifact_id)}
    return _text(_approval_link("primary", queued, approval_center_url=_text(approval_center_url), **fields).get("url"))


first_approval_url = primary_approval_url


def preferred_approval_review_url(payload: Mapping[str, object], *, harness: str) -> str | None:
    """Return the review link for a hook payload, else its approval center."""

    queued = payload.get("approval_requests")
    keys = ("approval_center_url", "primary_approval_request_id", "artifact_id", "primary_approval_url")
    fields = {key: _text(payload.get(key)) for key in keys}
    link = _approval_link("preferred", queued if isinstance(queued, list) else None, harness=harness, **fields)
    return _text(link.get("url")) or (fields["approval_center_url"] or "").strip() or None


def queue_blocked_approvals(
    *,
    detection: HarnessDetection,
    evaluation: dict[str, object],
    store: GuardStore,
    approval_center_url: str,
    now: str | None = None,
    notify: bool = True,
    prompt_shown: bool = True,
    redaction_level: str = "full",
    continuation_operation: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    items = evaluation.get("artifacts")
    if not isinstance(items, list):
        return []
    reviewable = [item for item in items if isinstance(item, dict) and _needs_review(item)]
    if not reviewable:
        return []
    timestamp = now or _now()
    artifacts = {artifact.artifact_id: artifact for artifact in detection.artifacts}
    observed_at = parse_aware_timestamp(timestamp)
    facts = continuation_offer_facts(
        store, harness=detection.harness, operation=continuation_operation or None, observed_at=observed_at
    )
    try:
        cwd: str | None = str(Path.cwd())
    except OSError:
        cwd = None
    continuation = {
        "harness": facts.harness,
        "original_hook_attached": facts.original_hook_attached,
        "wait_deadline": facts.wait_deadline.isoformat() if facts.wait_deadline is not None else None,
        "opaque_target_id": facts.opaque_target_id,
        "session_target_verified": facts.session_target_verified,
        "now": observed_at.isoformat(),
        "correlation_candidates": [facts.metadata.get(key) for key in ("correlationId", "correlation_id")],
    }
    payloads: list[dict[str, object]] = []
    # One store write per item keeps the former order: each request is
    # written, read back and announced before the next one is written.
    # The resident derives the request's surfaces, incident copy and
    # continuation snapshot; Python keeps the notices.
    try:
        for item in reviewable:
            artifact = artifacts.get(str(item["artifact_id"]))
            queued, error = store.queue_blocked_approvals(
                {
                    "harness": detection.harness,
                    "items": [item],
                    "artifacts": {} if artifact is None else {artifact.artifact_id: _queue_artifact(artifact)},
                    "approval_center_url": approval_center_url,
                    "now": timestamp,
                    "prompt_shown": prompt_shown,
                    "redaction_level": redaction_level,
                    "guard_version": _current_guard_version(),
                    "cwd": cwd,
                    "continuation": continuation,
                }
            )
            for entry in queued:
                request_id = str(entry["request_id"])
                # Read back before announcing, so a failed notice still leaves
                # the persisted request in the partial result.
                request_payload = store.get_approval_request(request_id)
                if request_payload is None:
                    raise RuntimeError(f"Persisted approval request not found: {request_id}")
                payloads.append(request_payload)
                if notify:
                    notice = cast(dict[str, str], entry["notice"])
                    group = _string_or_none(request_payload.get("queue_group_id"))
                    _notify_pending_approval(store=store, request=_QueuedNotice(**notice, queue_group_id=group))
            if error is not None:
                raise error
    except Exception as failure:
        # Requests written before the failure stay queued, so a caller that
        # keeps the deny can still point the user at them.
        failure.queued_approvals = payloads  # pyright: ignore[reportAttributeAccessIssue]
        raise
    return payloads


def approvals_queued_before(error: BaseException) -> list[dict[str, object]]:
    """Requests a failed ``queue_blocked_approvals`` call had already persisted."""

    queued = getattr(error, "queued_approvals", None)
    return list(queued) if isinstance(queued, list) else []


def _needs_review(item: Mapping[str, object]) -> bool:
    if not str(item.get("artifact_id") or ""):
        return False
    action = normalize_guard_action_result(item.get("policy_action"), unknown_action="require-reapproval").action
    return action in {"require-reapproval", "review"}


def _queue_artifact(artifact: GuardArtifact) -> dict[str, object]:
    artifact_risk = artifact_risk_profile(artifact)
    return {
        "wire": wire_artifact(artifact),
        **{key: artifact.metadata.get(key) for key in _QUEUE_METADATA_KEYS},
        "risk_summary": artifact_risk.summary,
        "risk_signals": [signal.explanation for signal in artifact_risk.signals],
    }


@dataclass(frozen=True, slots=True)
class _QueuedNotice:
    """The persisted request fields a desktop notice reads."""

    request_id: str
    harness: str
    workspace: str | None
    approval_url: str
    artifact_name: str
    risk_headline: str | None
    trigger_summary: str | None
    queue_group_id: str | None = None


def silent_review_center_url(guard_home: Path) -> str:
    """Loopback origin stored on a silent review. Does not start the daemon."""

    from .daemon.manager import guard_daemon_url_for_home

    return guard_daemon_url_for_home(guard_home)


def record_unprompted_review(
    *,
    detection: HarnessDetection,
    evaluation: Mapping[str, object],
    store: GuardStore,
    approval_center_url: str | None = None,
    now: str | None = None,
    redaction_level: str = "full",
    continuation_operation: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    """Persist a blocked review for the inbox and cloud outbox without prompting."""

    import sqlite3

    try:
        return queue_blocked_approvals(
            detection=detection,
            evaluation=dict(evaluation),
            store=store,
            approval_center_url=approval_center_url or silent_review_center_url(store.guard_home),
            now=now,
            notify=False,
            prompt_shown=False,
            redaction_level=redaction_level,
            continuation_operation=continuation_operation,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        # Exception text can include tool input. Keep the class only.
        _LOGGER.warning("Silent review stayed blocked without an inbox row (%s)", type(error).__name__)
        return []


@_serialize_approval_resolution
def apply_approval_resolution(
    *,
    store: GuardStore,
    request_id: str,
    action: str,
    scope: str,
    workspace: str | None,
    reason: str | None,
    now: str | None = None,
    return_queue_result: bool = False,
    resolve_scope_matches: bool = True,
    approval_gate_input: ApprovalGateInput | None = None,
    approval_gate_grant: ApprovalGateGrant | None = None,
    approval_gate_subject: str | None = None,
    persist_policy: bool | None = None,
    scope_contract_version: str | None = None,
    scope_contract_digest: str | None = None,
    mcp_grant_target: object | None = None,
    mcp_grant_duration: object | None = None,
    local_tool_grant_target: object | None = None,
    local_tool_grant_duration: object | None = None,
) -> dict[str, object]:
    request = store.get_approval_request(request_id, derive_scope=False)
    if request is None:
        raise ApprovalRequestNotFoundError(f"Unknown approval request: {request_id}")
    if request["status"] != "pending":
        raise ApprovalRequestAlreadyResolvedError(f"Approval request already resolved: {request_id}")
    require_resolvable_approval_request(request, guard_home=store.guard_home)
    from .native_bash_review_preflight import require_verified_bash_review

    require_verified_bash_review(store, request, require_execution=action == "allow" or persist_policy is True)
    from .store_base import _canonical_utc_timestamp

    resolved_at = _canonical_utc_timestamp(now or _now())
    temporary_mcp_selection: TemporaryMcpGrantSelection | None = None
    if (mcp_grant_target is None) != (mcp_grant_duration is None):
        raise ValueError("incomplete_temporary_mcp_approval")
    if mcp_grant_target is not None and local_tool_grant_target is not None:
        raise ValueError("mixed_temporary_grant_modes")
    if mcp_grant_target is not None:
        if action != "allow" or scope != "artifact":
            raise ValueError("temporary_mcp_approval_requires_artifact_allow")
        temporary_mcp_selection = parse_temporary_mcp_grant_selection(
            request,
            target=mcp_grant_target,
            duration=mcp_grant_duration,
            now=resolved_at,
        )
    local_tool_selection: LocalToolGrantSelection | None = None
    if (local_tool_grant_target is None) != (local_tool_grant_duration is None):
        raise ValueError("incomplete_local_tool_approval")
    if local_tool_grant_target is not None:
        if action != "allow" or scope != "artifact":
            raise ValueError("local_tool_approval_requires_artifact_allow")
        if persist_policy is True:
            raise ValueError("local_tool_approval_cannot_be_remembered")
        local_tool_selection = parse_local_tool_grant_selection(
            request,
            target=local_tool_grant_target,
            duration=local_tool_grant_duration,
            now=resolved_at,
            harness=str(request["harness"]),
            reason=reason,
        )
    # One resident ask settles the whole resolution: the scope the choice
    # resolves to, whether it may be remembered against the request's exact
    # action, and whether an allow has any binding left to run under. The
    # contract and exact-action token it resolved against ride back with it.
    selection = resolve_request_scope_selection(
        request,
        action=action,
        requested_scope=scope,
        contract_version=scope_contract_version,
        contract_digest=scope_contract_digest,
        persist_policy=persist_policy,
        ask_persistence=True,
        guard_home=store.guard_home,
    )
    if selection.contract is None:
        raise ApprovalScopeUnavailableError
    contract = selection.contract
    exact_token = selection.exact_token
    requested_scope = selection.requested_scope
    scope = selection.applied_scope
    persist_policy = selection.persist_policy
    request_artifact_id = _string_or_none(request.get("artifact_id"))
    request_artifact_hash = _string_or_none(request.get("artifact_hash"))
    resolved_workspace = resolve_request_workspace_scope(request, workspace) if scope == "workspace" else None
    # Only a workspace-scoped decision is stored under a package workspace key,
    # so only that scope asks the resident for one.  Every other scope ignored
    # the answer, and asking anyway made each one depend on a resident it never
    # needed - a shell "allow once" cannot fail because a package key could not
    # be derived.
    if scope == "workspace":
        try:
            portable_package_workspace = package_request_portable_workspace_scope(
                artifact_id=request_artifact_id,
                artifact_hash=request_artifact_hash,
                artifact_type=_string_or_none(request.get("artifact_type")),
                execution_context=package_execution_context_from_scanner_evidence(request.get("scanner_evidence")),
                guard_home=store.guard_home,
            )
        except NativePackageWorkspaceScopeError as error:
            # Every other resident scope failure here is an unavailable scope, and
            # the callers catch it as one.  This one is a ``RuntimeError``, so left
            # alone it would walk past those handlers and out of the CLI.
            raise ApprovalScopeUnavailableError from error
        if portable_package_workspace is not None:
            resolved_workspace = portable_package_workspace
    # The resident owns the decision identity, persistence mode, local-once row
    # and sibling selector; this function only executes the plan against the store.
    from .native_policy_snapshot_constants import NativePolicySnapshotError
    from .native_policy_snapshot_publisher import provision_native_verifier_key_for_store

    # The resident refuses every request until this home's verifier key exists.
    # A store that cannot derive one may still have a key from an earlier run, so
    # try the plan anyway and name the missing integrity backend if it fails.
    integrity_unavailable = False
    try:
        provision_native_verifier_key_for_store(store)
    except NativePolicySnapshotError:
        integrity_unavailable = True
    try:
        plan = native_approval_resolution_plan(
            request,
            guard_home=store.guard_home,
            action=action,
            scope=scope,
            persist_policy=persist_policy,
            temporary_mcp=temporary_mcp_selection is not None,
            local_tool=local_tool_selection is not None,
            resolve_scope_matches=resolve_scope_matches,
            requires_local_once=action == "allow" and requires_local_once_approval(request),
            resolved_workspace=resolved_workspace,
            native_exact_token=exact_token if persist_policy is True and scope == "artifact" else None,
            resolved_at=resolved_at,
        )
    except ApprovalResolutionPlanUnavailableError as error:
        if integrity_unavailable:
            raise ApprovalResolutionPlanUnavailableError(INTEGRITY_UNAVAILABLE) from error
        raise
    planned = cast(Mapping[str, object], plan["decision"])
    decision = PolicyDecision(
        harness=str(planned["harness"]),
        scope=scope,
        action="allow" if planned["action"] == "allow" else "block",
        artifact_id=_string_or_none(planned.get("artifact_id")),
        artifact_hash=_string_or_none(planned.get("artifact_hash")),
        workspace=_string_or_none(planned.get("workspace")),
        publisher=_string_or_none(planned.get("publisher")),
        reason=reason,
        source="approval-gate",
    )
    resolved_gate_grant = require_approval_decision(
        store.guard_home,
        action=decision.action,
        scope=scope,
        approval_gate_input=approval_gate_input,
        approval_gate_grant=approval_gate_grant,
        subject=approval_gate_subject or f"approval-request:{request_id}",
        now=resolved_at,
    )
    persistence = plan["persistence"]
    persisted_rule = persistence == "persisted"
    local_once_fallback = False
    if persistence == "persisted":
        store.ensure_policy_integrity_ready_for_write(
            harness=decision.harness if decision.harness != "*" else None,
            approval_gate_grant=resolved_gate_grant,
            now=resolved_at,
        )
        store.upsert_policy(decision, resolved_at, approval_gate_grant=resolved_gate_grant)
    elif persistence == "once":
        once_decision = replace(decision, expires_at=_string_or_none(plan.get("once_expires_at")))
        store.ensure_policy_integrity_ready_for_write(
            harness=once_decision.harness if once_decision.harness != "*" else None,
            approval_gate_grant=resolved_gate_grant,
            now=resolved_at,
        )
        store.upsert_policy(
            once_decision,
            resolved_at,
            approval_gate_grant=resolved_gate_grant,
        )
    elif persistence == "exact_once":
        # "Do not remember" still authorizes the exact approved retry once.
        store.ensure_policy_integrity_ready_for_write(
            harness=decision.harness,
            approval_gate_grant=resolved_gate_grant,
            now=resolved_at,
        )
    local_once_row = plan.get("local_once")
    if isinstance(local_once_row, Mapping):
        local_once_fallback = _record_local_once_approval(
            store,
            request_id=request_id,
            row=local_once_row,
            created_at=resolved_at,
        )

    temporary_mcp_result: dict[str, object] | None = None
    temporary_mcp_resolved_ids: list[str] = []
    if temporary_mcp_selection is not None:
        temporary_decision = temporary_mcp_grant_decision(
            harness=str(request["harness"]),
            selection=temporary_mcp_selection,
            reason=reason,
            artifact_id=request_artifact_id or "",
            artifact_hash=request_artifact_hash or "",
        )
        store.ensure_policy_integrity_ready_for_write(
            harness=temporary_decision.harness,
            approval_gate_grant=resolved_gate_grant,
            now=resolved_at,
        )
        temporary_mcp_result, temporary_mcp_resolved_ids = store.apply_temporary_mcp_grant_resolution(
            request_id=request_id,
            decision=temporary_decision,
            selection=temporary_mcp_selection,
            reason=reason,
            resolved_at=resolved_at,
            approval_gate_grant=resolved_gate_grant,
        )
        if temporary_mcp_result.get("resolved") is not True:
            error = temporary_mcp_result.get("error")
            if error == "already_resolved":
                raise ApprovalRequestAlreadyResolvedError(f"Approval request already resolved: {request_id}")
            if error == "not_found":
                raise ApprovalRequestNotFoundError(f"Unknown approval request: {request_id}")
            if isinstance(error, str) and error:
                raise ValueError(error)
    if local_tool_selection is not None:
        local_tool_decision = local_tool_grant_decision(local_tool_selection)
        store.ensure_policy_integrity_ready_for_write(
            harness=local_tool_decision.harness,
            approval_gate_grant=resolved_gate_grant,
            now=resolved_at,
        )
        store.upsert_policy(
            local_tool_decision,
            resolved_at,
            approval_gate_grant=resolved_gate_grant,
        )

    matching = plan.get("matching")
    if return_queue_result:
        result = (
            temporary_mcp_result
            if temporary_mcp_result is not None
            else store.resolve_request_with_queue_result(
                request_id,
                resolution_action=action,
                resolution_scope=scope,
                reason=reason,
                resolved_at=resolved_at,
                approval_gate_grant=resolved_gate_grant,
            )
        )
        if result.get("resolved") is not True:
            error = result.get("error")
            if error == "already_resolved":
                raise ApprovalRequestAlreadyResolvedError(f"Approval request already resolved: {request_id}")
            if error == "not_found":
                raise ApprovalRequestNotFoundError(f"Unknown approval request: {request_id}")
            if isinstance(error, str) and error:
                raise ValueError(error)
        if isinstance(matching, Mapping):
            resolved_scope_ids = _resolve_matching_requests(
                store,
                matching,
                action=action,
                reason=reason,
                resolved_at=resolved_at,
                approval_gate_grant=resolved_gate_grant,
            )
            if resolved_scope_ids:
                _refresh_queue_result(store, result, resolved_scope_ids)
        _record_resolution_event(
            store,
            request_id,
            action,
            scope,
            resolved_at,
            persisted_rule=persisted_rule,
            local_once_fallback=local_once_fallback,
            retry_cannot_reuse_approval=RETRY_CANNOT_REUSE_APPROVAL in contract.restrictions,
        )
        issue_github_workflow_capability_for_resolution(store, request_id, resolved_at)
        result.update(scope_payload_for_request(request, contract))
        result["requested_scope"] = requested_scope
        result["applied_scope"] = scope
        if selection.warning is not None:
            result["scope_warning"] = selection.warning
        if temporary_mcp_selection is not None:
            result["temporary_mcp_grant"] = _temporary_mcp_grant_result(temporary_mcp_selection)
            if temporary_mcp_resolved_ids:
                _refresh_queue_result(store, result, temporary_mcp_resolved_ids)
        return result
    resolved_ids: list[str] = []
    if isinstance(matching, Mapping):
        resolved_ids = _resolve_matching_requests(
            store,
            matching,
            action=action,
            reason=reason,
            resolved_at=resolved_at,
            approval_gate_grant=resolved_gate_grant,
        )
    if request_id not in resolved_ids and temporary_mcp_result is None:
        store.resolve_approval_request(
            request_id,
            resolution_action=action,
            resolution_scope=scope,
            reason=reason,
            resolved_at=resolved_at,
            approval_gate_grant=resolved_gate_grant,
        )
    updated = store.get_approval_request(request_id, derive_scope=False)
    if updated is None:
        raise ValueError(f"Approval request disappeared: {request_id}")
    _record_resolution_event(
        store,
        request_id,
        action,
        scope,
        resolved_at,
        persisted_rule=persisted_rule,
        local_once_fallback=local_once_fallback,
        retry_cannot_reuse_approval=RETRY_CANNOT_REUSE_APPROVAL in contract.restrictions,
    )
    issue_github_workflow_capability_for_resolution(store, request_id, resolved_at)
    updated.update(scope_payload_for_request(request, contract))
    apply_scope_surfaces(updated)
    updated["requested_scope"] = requested_scope
    updated["applied_scope"] = scope
    if selection.warning is not None:
        updated["scope_warning"] = selection.warning
    if temporary_mcp_selection is not None:
        updated["temporary_mcp_grant"] = _temporary_mcp_grant_result(temporary_mcp_selection)
    if local_tool_selection is not None:
        updated["local_tool_grant"] = _local_tool_grant_result(local_tool_selection)
    return updated


def _temporary_mcp_grant_result(selection: TemporaryMcpGrantSelection) -> dict[str, object]:
    return {
        "target": selection.target,
        "duration": selection.duration,
        "expires_at": selection.expires_at,
        "server_name": selection.eligibility.server_name,
        "category": selection.eligibility.category,
    }


def _local_tool_grant_result(selection: LocalToolGrantSelection) -> dict[str, object]:
    return {
        "target": selection.target,
        "duration": selection.duration,
        "expires_at": selection.expires_at,
        "tool_name": selection.tool_name,
        "capability": selection.capability,
    }


def _append_guard_token_to_url(url: str, auth_token: str) -> str:
    """Append a fresh guard-token fragment to an approval URL."""
    parsed = urlparse(url)
    fragment_pairs = [
        (key, value) for key, value in parse_qsl(parsed.fragment, keep_blank_values=True) if key != "guard-token"
    ]
    fragment_pairs.append(
        (
            "guard-token",
            build_local_dashboard_session_token(
                auth_token=auth_token,
                surface="approval-center",
            ),
        )
    )
    return urlunparse(parsed._replace(fragment=urlencode(fragment_pairs)))


def _notify_pending_approval(*, store: GuardStore, request: _QueuedNotice) -> None:
    try:
        config = load_guard_config(
            store.guard_home,
            Path(request.workspace) if request.workspace is not None else None,
        )
    except Exception:
        config = None
    if config is not None and not config.desktop_notifications:
        return
    try:
        if store.approval_desktop_notified_at(request.request_id) is not None:
            return
    except ApprovalScopeUnavailableError:
        # The request is already queued; the notification is best effort.
        return
    auth_token = load_guard_daemon_auth_token(store.guard_home)
    approval_url = request.approval_url
    if auth_token:
        approval_url = _append_guard_token_to_url(approval_url, auth_token)
    notify_pending_approval_once(
        DesktopApprovalNotification(
            request_id=request.request_id,
            title=_approval_notification_title(request),
            message=_approval_notification_message(request),
            approval_url=approval_url,
        ),
        on_success=lambda: _mark_desktop_notified(store, request.request_id),
    )


def notify_connector_setup(store: object, queued: Mapping[str, object], *, connector_name: str) -> None:
    """Raise the setup notice for a native review row already queued under a connector group.

    Best effort, as ``_notify_pending_approval`` is: the row is in the Inbox either way. Commands that wait on
    one connector share a group, and the store answers with its first notified sibling's marker, so only the
    first command raises a notice.
    """

    fields = {key: _string_or_none(queued.get(key)) for key in ("request_id", "harness", "approval_url")}
    group = _string_or_none(queued.get("queue_group_id"))
    request_id, harness, approval_url = fields["request_id"], fields["harness"], fields["approval_url"]
    if request_id is None or harness is None or approval_url is None or group is None:
        return
    notice = _QueuedNotice(
        request_id=request_id,
        harness=harness,
        workspace=_string_or_none(queued.get("workspace")),
        approval_url=approval_url,
        artifact_name=connector_name,
        risk_headline=connector_name,
        trigger_summary=None,
        queue_group_id=group,
    )
    with contextlib.suppress(Exception):
        _notify_pending_approval(store=cast(GuardStore, store), request=notice)


def _mark_desktop_notified(store: GuardStore, request_id: str) -> None:
    # This process already remembers the notification; a lost marker only
    # lets another process notify once more.
    with contextlib.suppress(ApprovalScopeUnavailableError):
        store.mark_approval_desktop_notified(request_id, _now())


def _is_connector_setup(request: _QueuedNotice) -> bool:
    return (request.queue_group_id or "").startswith("connector:")


def _approval_notification_title(request: _QueuedNotice) -> str:
    # Commands of one connector share a single notice, raised by the first.
    return "HOL Guard: a connector needs setup" if _is_connector_setup(request) else "HOL Guard needs approval"


def _approval_notification_message(request: _QueuedNotice) -> str:
    subject = request.risk_headline or request.trigger_summary or request.artifact_name
    harness = request.harness.replace("-", " ").title()
    if _is_connector_setup(request):
        message = f"{harness} is waiting on a connector Guard has not set up yet: {subject}"
    else:
        message = f"{harness} wants approval: {subject}"
    if len(message) <= 180:
        return message
    return f"{message[:177].rstrip()}..."


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _record_resolution_event(
    store: GuardStore,
    request_id: str,
    action: str,
    scope: str,
    resolved_at: str,
    *,
    persisted_rule: bool,
    local_once_fallback: bool = False,
    retry_cannot_reuse_approval: bool = False,
) -> None:
    store.add_event(
        "approval.resolved",
        {
            "request_id": request_id,
            "action": action,
            "scope": scope,
            "persisted_rule": persisted_rule,
            "local_once_fallback": local_once_fallback,
        },
        resolved_at,
    )
    store.add_event(
        "rule.remembered.local" if persisted_rule else "approval.once",
        {
            "request_id": request_id,
            "action": action,
            "scope": scope,
            "local_once_fallback": local_once_fallback,
        },
        resolved_at,
    )
    if action == "allow" and persisted_rule:
        store.add_event(
            "guard.protection.ask_once_remembered",
            {
                "request_id": request_id,
                "scope": scope,
                "local_once_fallback": local_once_fallback,
            },
            resolved_at,
        )
    _enqueue_memory_decision_for_resolution(
        store,
        request_id=request_id,
        action=action,
        scope=scope,
        resolved_at=resolved_at,
        # Only a saved rule lets an unbound native retry run; a one-time
        # approval of it leaves the action blocked.
        retry_blocked=action == "allow" and not persisted_rule and retry_cannot_reuse_approval,
    )


def _enqueue_memory_decision_for_resolution(
    store: GuardStore,
    *,
    request_id: str,
    action: str,
    scope: str,
    resolved_at: str,
    retry_blocked: bool = False,
) -> None:
    """Feed the local-to-cloud memory candidate pipeline for this decision.

    Defensive by design: a missing request, missing cloud pairing, or any store
    error must never break the local approval that already succeeded.
    """
    try:
        request = store.get_approval_request(request_id, derive_scope=False)
    except Exception:
        request = None
    if not request:
        return
    enqueue_memory_decision_event(
        store,
        request=request,
        action=action,
        scope=scope,
        resolved_at=resolved_at,
        retry_blocked=retry_blocked,
    )


def _refresh_queue_result(
    store: GuardStore,
    result: dict[str, object],
    resolved_scope_ids: list[str],
) -> None:
    page = store.list_pending_approval_summaries(limit=10)
    next_request = store.get_next_pending_request()
    remaining_count = _non_negative_int(page.get("total_pending_count"))
    result["remaining_pending_count"] = remaining_count
    result["next_selectable_request_id"] = next_request["request_id"] if next_request is not None else None
    result["remaining_pending_summaries"] = page["items"]
    previous_ids = result.get("resolved_scope_ids")
    existing_ids = (
        [str(value) for value in previous_ids if isinstance(value, str)] if isinstance(previous_ids, list) else []
    )
    combined_ids = [*existing_ids, *resolved_scope_ids]
    result["resolved_scope_ids"] = list(dict.fromkeys(combined_ids))
    if remaining_count == 0:
        result["resolution_summary"] = "Decision saved. No actions are awaiting a decision."
    elif remaining_count == 1:
        result["resolution_summary"] = "Decision saved. 1 action is awaiting a decision."
    else:
        result["resolution_summary"] = f"Decision saved. {remaining_count} actions are awaiting a decision."


def approval_center_hint(
    *,
    context: HarnessContext,
    harness: str,
    approval_center_url: str,
    queued: list[dict[str, object]],
    managed_install: dict[str, object] | None = None,
    request_id: str | None = None,
    artifact_id: str | None = None,
    review_url: str | None = None,
) -> str:
    del context
    flow = approval_prompt_flow(harness, managed_install=managed_install)
    count = len(queued)
    risk_summary = _queue_risk_summary(queued)
    resolved_review_url = review_url or (
        primary_approval_url(
            queued,
            harness=harness,
            approval_center_url=approval_center_url,
            request_id=request_id,
            artifact_id=artifact_id,
        )
        or approval_center_url
    )
    return (
        f"Guard queued {count} approval request{'s' if count != 1 else ''} for {harness}. "
        f"{flow['summary']} "
        f"Review them in the Guard approval center at {resolved_review_url}. "
        f"{risk_summary} "
        f"{flow['fallback_hint']}"
    )


def attach_primary_approval_link(
    payload: dict[str, object],
    *,
    harness: str | None = None,
    approval_center_url: str | None = None,
    request_id: str | None = None,
    artifact_id: str | None = None,
) -> None:
    """Bind primary approval fields to the request created by this block."""

    queued = payload.get("approval_requests")
    if not isinstance(queued, list):
        return
    operation = payload.get("operation")
    operation_ids = operation.get("approval_request_ids") if isinstance(operation, Mapping) else None
    request_ids = [
        item for ids in (payload.get("approval_request_ids"), operation_ids) if isinstance(ids, list) for item in ids
    ]
    link = _approval_link(
        "attach",
        queued,
        harness=_text(harness),
        approval_center_url=_text(approval_center_url),
        request_id=_text(request_id),
        artifact_id=_text(artifact_id),
        payload_artifact_id=_text(payload.get("artifact_id")),
        primary_approval_request_id=_text(payload.get("primary_approval_request_id")),
        approval_request_ids=[item for item in request_ids if isinstance(item, str)],
    )
    for key, field in (("primary_approval_request_id", "request_id"), ("primary_approval_url", "url")):
        if (value := _text(link.get(field))) is not None:
            payload[key] = value


def _live_hook_verification(
    managed_installs: Sequence[Mapping[str, object]],
    store: GuardStore,
) -> dict[str, bool]:
    context = HarnessContext(
        home_dir=Path.home().resolve(),
        workspace_dir=None,
        guard_home=store.guard_home,
    )
    verified: dict[str, bool] = {}
    for install in managed_installs:
        harness = install.get("harness")
        if not isinstance(harness, str) or install.get("active") is not True:
            continue
        try:
            if harness == "codex":
                from .codex_hook_health import codex_runtime_hooks_verified

                verified[harness] = codex_runtime_hooks_verified(context)
                continue
            if harness == "cursor":
                from .cursor_hook_health import cursor_runtime_hooks_verified

                proven = cursor_runtime_hooks_verified(context)
                if proven is None:
                    continue
                verified[harness] = proven
                continue
            if harness == "grok":
                from .adapters.grok import grok_runtime_hooks_verified

                verified[harness] = grok_runtime_hooks_verified(context)
                continue
            verified[harness] = verify_managed_install_proof(install.get("manifest"), context) is True
        except (ImportError, OSError, RuntimeError, TypeError, ValueError):
            continue
    return verified


def _canonical_managed_installs_for_health(
    managed_installs: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    canonical: dict[str, tuple[tuple[bool, bool], dict[str, object]]] = {}
    for install in managed_installs:
        harness = install.get("harness")
        if not isinstance(harness, str):
            continue
        try:
            canonical_harness = get_adapter(harness).harness
        except (ImportError, RuntimeError, TypeError, ValueError):
            canonical_harness = harness
        candidate = dict(install)
        candidate["harness"] = canonical_harness
        exact = harness == canonical_harness
        priority = (install.get("active") is True, exact)
        existing = canonical.get(canonical_harness)
        if existing is None or priority > existing[0]:
            canonical[canonical_harness] = (priority, candidate)
    return [canonical[harness][1] for harness in sorted(canonical)]


def build_runtime_snapshot(
    *,
    store: GuardStore,
    approval_center_url: str | None,
    now: str | None = None,
    request_limit: int = 200,
    receipt_limit: int = 25,
    active_request_id: str | None = None,
    include_items: bool = True,
    containment_health: object = None,
    serving_runtime: Mapping[str, object] | None = None,
) -> dict[str, object]:
    # Each store call otherwise opens its own connection. That made this
    # control-plane read take several seconds on an ordinary local store.
    with store.connection_scope():
        return _build_runtime_snapshot(
            store=store,
            approval_center_url=approval_center_url,
            now=now,
            request_limit=request_limit,
            receipt_limit=receipt_limit,
            active_request_id=active_request_id,
            include_items=include_items,
            containment_health=containment_health,
            serving_runtime=serving_runtime,
        )


def _build_runtime_snapshot(
    *,
    store: GuardStore,
    approval_center_url: str | None,
    now: str | None = None,
    request_limit: int = 200,
    receipt_limit: int = 25,
    active_request_id: str | None = None,
    include_items: bool = True,
    containment_health: object = None,
    serving_runtime: Mapping[str, object] | None = None,
) -> dict[str, object]:
    queue_page = store.list_pending_approval_summaries(limit=1, exclude_watch_only=True)
    queue_items = queue_page["items"] if isinstance(queue_page["items"], list) else []
    pending_count = _non_negative_int(queue_page.get("total_pending_count"))
    pending_requests = store.list_approval_requests(limit=request_limit) if include_items else []
    active_request = store.get_approval_request(active_request_id) if active_request_id else None
    active_is_pending = active_request is not None and active_request.get("status") == "pending"
    first_request_id = str(queue_items[0]["request_id"]) if queue_items else None
    next_request_id = active_request_id if active_is_pending else first_request_id
    latest_receipts = store.list_receipts(limit=receipt_limit) if receipt_limit > 0 else []
    snapshot_now = now or _now()
    config = maybe_auto_revert_watch(store.guard_home)
    latest_connect_state = _build_latest_connect_state(store, snapshot_now)
    oauth_storage_health = store.get_oauth_local_credential_health()
    cloud_context = _build_runtime_cloud_context(
        store,
        latest_connect_state=latest_connect_state,
        oauth_storage_health=oauth_storage_health,
    )
    proof_status = cloud_context.pop("proof_status")
    trust_status = store.get_cached_policy_trust_status()
    managed_installs = store.list_managed_installs()
    health_managed_installs = _canonical_managed_installs_for_health(managed_installs)
    hook_verification = _live_hook_verification(health_managed_installs, store)
    runtime_state = store.get_runtime_state()
    health_runtime_state = dict(runtime_state) if runtime_state is not None else None
    if health_runtime_state is None and serving_runtime is not None:
        # The store row is gone but this process is serving requests. Report a
        # truthful "missing registration" state instead of claiming the runtime
        # is offline; the heartbeat writer re-registers the row.
        health_runtime_state = dict(serving_runtime)
        health_runtime_state["registration_status"] = "missing"
        if approval_center_url is not None:
            health_runtime_state["approval_center_url"] = approval_center_url
    if health_runtime_state is not None and containment_health is not None:
        health_runtime_state["containment_health"] = containment_health
    try:
        protection_health: dict[str, object] | None = build_runtime_protection_health(
            store=store,
            guard_home=store.guard_home,
            runtime_state=health_runtime_state,
            managed_installs=health_managed_installs,
            hook_verification=hook_verification,
            trust_status=trust_status,
            now=datetime.fromisoformat(snapshot_now.replace("Z", "+00:00")),
        )
    except NativeProtectionHealthError as error:
        # Only the native runtime says whether this machine is protected. With
        # it unreachable there is no report to show and no state to claim, so
        # the snapshot carries neither and the headline falls to degraded. The
        # reason code is the only thing that tells a missing runtime apart from
        # one that answered something unusable, and snapshots are polled, so it
        # goes to the log at debug.
        _LOGGER.debug("protection health report unavailable: %s", error)
        protection_health = None
    headline = _runtime_headline(
        store,
        pending_count=pending_count,
        runtime_state_present=health_runtime_state is not None,
        protection_state=str(protection_health["state"]) if protection_health is not None else "",
    )
    return {
        "generated_at": snapshot_now,
        "approval_center_url": approval_center_url,
        "runtime_state": health_runtime_state,
        "oauth_storage_health": oauth_storage_health,
        "device": _build_runtime_device_context(store),
        "latest_connect_state": latest_connect_state,
        "proof_status": proof_status,
        "pending_count": pending_count,
        "queue_summary": {
            "active_request_id": active_request_id if active_is_pending else None,
            "next_request_id": next_request_id,
            "remaining_pending_count": pending_count,
            "next_selectable_request_id": next_request_id,
        },
        "next_request_id": next_request_id,
        "receipt_count": store.count_receipts(),
        **headline,
        "thread_count": threading.active_count(),
        "items": pending_requests,
        "latest_receipts": latest_receipts,
        "managed_installs": managed_installs,
        "cloud_command_capability": command_capability_status(store, now=snapshot_now),
        "supply_chain": build_local_supply_chain_posture(store, config, now=snapshot_now),
        **cloud_context,
        "trust_status": trust_status,
        "protection_health": protection_health,
        "protection_capabilities": protection_capability_payloads(),
        "protection_posture": config.protection_posture,
        **harness_posture_summary(config),
    }


def approval_prompt_flow(
    harness: str,
    *,
    managed_install: dict[str, object] | None = None,
) -> dict[str, object]:
    try:
        flow = get_adapter(harness).approval_flow(managed_install=managed_install)
    except ValueError:
        flow = {}
    return {
        "tier": str(flow.get("tier") or "approval-center"),
        "summary": str(flow.get("summary") or ""),
        "fallback_hint": str(flow.get("fallback_hint") or ""),
        "prompt_channel": str(flow.get("prompt_channel") or "browser"),
        "auto_open_browser": bool(flow.get("auto_open_browser", True)),
    }


def approval_delivery_payload(flow: dict[str, object]) -> dict[str, object]:
    auto_open_browser = bool(flow.get("auto_open_browser"))
    return {
        "destination": "browser" if auto_open_browser else "harness",
        "prompt_channel": str(flow.get("prompt_channel") or "browser"),
        "summary": str(flow.get("summary") or ""),
    }


def wait_for_approval_requests(
    *,
    store: GuardStore,
    request_ids: list[str],
    timeout_seconds: int,
    poll_interval: float = 0.01,
    stop_on_missing: bool = False,
) -> dict[str, object]:
    if not request_ids:
        return {
            "resolved": False,
            "pending_request_ids": [],
            "items": [],
            "reason": "no_approval_requests",
        }
    deadline = time.monotonic() + max(timeout_seconds, 0)
    while True:
        items = [store.get_approval_request(request_id) for request_id in request_ids]
        if stop_on_missing:
            missing = [request_id for request_id, item in zip(request_ids, items, strict=True) if item is None]
            if missing:
                return {"resolved": False, "missing_request_ids": missing, "items": []}
        resolved_items = [item for item in items if isinstance(item, dict) and item.get("status") == "resolved"]
        pending_ids = [
            request_id
            for request_id, item in zip(request_ids, items, strict=True)
            if not isinstance(item, dict) or item.get("status") != "resolved"
        ]
        if not pending_ids:
            return {"resolved": True, "pending_request_ids": [], "items": resolved_items}
        if time.monotonic() >= deadline:
            return {"resolved": False, "pending_request_ids": pending_ids, "items": resolved_items}
        time.sleep(poll_interval)


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_matching_requests(
    store: GuardStore,
    matching: Mapping[str, object],
    *,
    action: str,
    reason: str | None,
    resolved_at: str,
    approval_gate_grant: ApprovalGateGrant | None,
) -> list[str]:
    """Resolve the sibling requests the resident selected for this resolution."""

    scope = str(matching["scope"])
    return store.resolve_matching_approval_requests(
        harness=_string_or_none(matching.get("harness")),
        scope=scope,
        artifact_id=_string_or_none(matching.get("artifact_id")),
        artifact_hash=_string_or_none(matching.get("artifact_hash")),
        workspace=_string_or_none(matching.get("workspace")),
        publisher=_string_or_none(matching.get("publisher")),
        resolution_action=action,
        resolution_scope=scope,
        reason=reason,
        resolved_at=resolved_at,
        approval_gate_grant=approval_gate_grant,
    )


def _record_local_once_approval(
    store: GuardStore,
    *,
    request_id: str,
    row: Mapping[str, object],
    created_at: str,
) -> bool:
    approval_id = store.record_local_once_approval(
        request_id=request_id,
        harness=str(row["harness"]),
        artifact_id=_string_or_none(row.get("artifact_id")),
        artifact_hash=_string_or_none(row.get("artifact_hash")),
        workspace=_string_or_none(row.get("workspace")),
        publisher=_string_or_none(row.get("publisher")),
        action=str(row["action"]),
        created_at=created_at,
        expires_at=str(row["expires_at"]),
    )
    return approval_id is not None


def _build_runtime_cloud_context(
    store: GuardStore,
    latest_connect_state: dict[str, object] | None,
    *,
    oauth_storage_health: dict[str, object] | None = None,
) -> dict[str, object]:
    cloud_profile = store.get_cloud_sync_profile()
    if oauth_storage_health is None:
        oauth_storage_health = store.get_oauth_local_credential_health()
    oauth_repair_required = (
        bool(oauth_storage_health.get("configured")) and oauth_storage_health.get("state") == "degraded"
    )
    connect_retry_required = connect_retry_required_from_state(latest_connect_state)
    connect_retry_refresh_race = connect_retry_refresh_race_from_state(latest_connect_state)
    sync_url = cloud_profile["sync_url"] if cloud_profile is not None else None
    sync_summary = store.get_sync_payload("sync_summary") or {}
    alert_preferences = store.get_sync_payload("alert_preferences") or {}
    policy_bundle, cached_policy_bundle_error = synced_policy_bundle_validation(store)
    policy_bundle = policy_bundle or {}
    policy_defaults = policy_bundle.get("policyDefaults")
    remote_policy = policy_defaults if isinstance(policy_defaults, dict) else {}
    policy_bundle_last_error = _sync_payload_dict(store, "policy_bundle_last_error")
    remote_payload_active = any((sync_summary, remote_policy, alert_preferences))
    cloud_state = resolve_guard_cloud_state(
        sync_configured=cloud_profile is not None,
        sync_completed=bool(sync_summary),
        remote_payload_active=remote_payload_active,
        oauth_repair_required=oauth_repair_required,
        connect_retry_required=connect_retry_required,
    )
    cloud_status = _runtime_cloud_status(
        store,
        latest_connect_state,
        cloud_state=cloud_state,
        sync_configured=cloud_profile is not None,
        oauth_repair_required=oauth_repair_required,
        connect_retry_required=connect_retry_required,
        connect_retry_refresh_race=connect_retry_refresh_race,
        shared_proof_recorded=bool(sync_summary) or remote_payload_active,
        policy_ack=_policy_ack_facts(store, policy_bundle),
        sync_url=sync_url if isinstance(sync_url, str) else None,
    )
    guard_urls = {key: cloud_status[key] for key in _GUARD_URL_FIELDS}
    oauth_credentials = store.get_oauth_local_credentials(allow_primary=True)
    cloud_user_profile: dict[str, str] | None = None
    cloud_plan_id: str | None = None
    if isinstance(oauth_credentials, dict):
        raw_profile = oauth_credentials.get("cloud_user_profile")
        if isinstance(raw_profile, dict):
            cloud_user_profile = {str(k): str(v) for k, v in raw_profile.items()}
        raw_plan_id = oauth_credentials.get("supply_chain_plan_id")
        if isinstance(raw_plan_id, str) and raw_plan_id:
            cloud_plan_id = raw_plan_id
    cloud_workspace_id = store.get_cloud_workspace_id()
    return {
        "sync_configured": cloud_profile is not None,
        "cloud_user_profile": cloud_user_profile,
        "cloud_workspace_id": cloud_workspace_id,
        "cloud_state": cloud_state,
        "cloud_state_label": cloud_status["cloud_state_label"],
        "cloud_state_detail": cloud_status["cloud_state_detail"],
        "cloud_sync_health": cloud_status["cloud_sync_health"],
        "cloud_pairing_state": {
            "state": cloud_state,
            "label": cloud_status["cloud_state_label"],
            "detail": cloud_status["cloud_state_detail"],
            "sync_configured": cloud_profile is not None,
            "cloud_user_profile": cloud_user_profile,
            "workspace_id": cloud_workspace_id,
            "plan_id": cloud_plan_id,
            **guard_urls,
        },
        **guard_urls,
        "cloud_policy_bundle_hash": _optional_string(policy_bundle.get("bundleHash")),
        "cloud_policy_bundle_version": _optional_string(policy_bundle.get("bundleVersion")),
        "cloud_policy_rollout_state": _optional_string(policy_bundle.get("rolloutState")),
        "cloud_policy_sync_error": cached_policy_bundle_error
        or _optional_string(policy_bundle_last_error.get("reason")),
        "cloud_policy_last_ack_at": cloud_status["cloud_policy_last_ack_at"],
        "team_policy_active": False,
        "proof_status": cloud_status["proof_status"],
    }


def _runtime_cloud_status(
    store: GuardStore,
    latest_connect_state: dict[str, object] | None,
    *,
    cloud_state: str,
    sync_configured: bool,
    oauth_repair_required: bool,
    connect_retry_required: bool,
    connect_retry_refresh_race: bool,
    shared_proof_recorded: bool,
    policy_ack: dict[str, object],
    sync_url: str | None,
) -> dict[str, Any]:
    """Ask the native runtime for the snapshot's Guard Cloud status copy.

    The copy is display only, so an unavailable runtime reports the status as
    unavailable rather than guessing one.
    """
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    pending_events = store.count_guard_events_v1(uploaded=False)
    event_summary = _sync_payload_dict(store, "guard_events_v1_summary")
    proof = _connect_state_proof(latest_connect_state.get("proof") if latest_connect_state is not None else None)
    reply: object = None
    try:
        reply = native_runner_authority(
            "runtime_cloud_status",
            {
                "connect_state": latest_connect_state,
                "cloud_state": cloud_state,
                "sync_configured": sync_configured,
                "oauth_repair_required": oauth_repair_required,
                "connect_retry_required": connect_retry_required,
                "connect_retry_refresh_race": connect_retry_refresh_race,
                "shared_proof_recorded": shared_proof_recorded,
                "pending_events": pending_events,
                "event_summary": {key: event_summary[key] for key in _EVENT_SUMMARY_FIELDS if key in event_summary},
                "synced_at": [
                    event_summary.get("synced_at"),
                    _sync_payload_dict(store, "sync_summary").get("synced_at"),
                    _sync_payload_dict(store, "runtime_session_summary").get("synced_at"),
                ],
                "policy_ack": policy_ack,
                "sync_url": sync_url,
            },
            guard_home=store.guard_home,
        )
    except NativeRunnerAuthorityError as error:
        _LOGGER.debug("runtime cloud status unavailable: %s", error)
    status: dict[str, Any]
    if _is_runtime_cloud_status(reply):
        status = reply
    else:
        # `failed` is a state every status surface already shows with its own
        # label and detail, so the load error stays visible.
        unavailable = {"state": "failed", "label": "Cloud status unavailable", "detail": _CLOUD_STATUS_UNAVAILABLE}
        request_id = latest_connect_state.get("request_id") if latest_connect_state is not None else None
        status = {
            "proof_status": {**unavailable, "request_id": request_id},
            "cloud_state_label": unavailable["label"],
            "cloud_state_detail": _CLOUD_STATUS_UNAVAILABLE,
            "cloud_sync_health": {
                **unavailable,
                "pending_events": pending_events,
                "last_synced_at": None,
                "next_retry_after": None,
            },
            "cloud_policy_last_ack_at": None,
            **_fallback_guard_urls(sync_url),
        }
    status["proof_status"] = {**status["proof_status"], **proof}
    return status


def _fallback_guard_urls(sync_url: str | None) -> dict[str, str]:
    """The Guard page links on the configured sync origin when the runtime is out.

    The published links are the fallback only without a usable sync URL, so a
    machine paired with another Guard Cloud never links to the public one.
    """

    parsed = urlparse(sync_url or "")
    if not parsed.scheme or not parsed.netloc:
        return {
            "dashboard_url": GUARD_DASHBOARD_URL,
            "inbox_url": GUARD_INBOX_URL,
            "fleet_url": GUARD_FLEET_URL,
            "connect_url": GUARD_CONNECT_URL,
        }
    dashboard_url = f"{parsed.scheme}://{parsed.netloc}/guard"
    return {
        "dashboard_url": dashboard_url,
        "inbox_url": f"{dashboard_url}/inbox",
        "fleet_url": f"{dashboard_url}/protect",
        "connect_url": f"{dashboard_url}/connect",
    }


def _is_runtime_cloud_status(status: object) -> TypeGuard[dict[str, Any]]:
    """Whether a native reply carries every field the snapshot reads."""

    return (
        isinstance(status, dict)
        and isinstance(status.get("proof_status"), dict)
        and isinstance(status.get("cloud_state_label"), str)
        and isinstance(status.get("cloud_state_detail"), str)
        and isinstance(status.get("cloud_sync_health"), dict)
        and isinstance(status.get("cloud_policy_last_ack_at", 0), (str, type(None)))
        and all(isinstance(status.get(key), str) for key in _GUARD_URL_FIELDS)
    )


def _sync_payload_dict(store: GuardStore, key: str) -> dict[str, object]:
    payload = store.get_sync_payload(key) or {}
    return payload if isinstance(payload, dict) else {}


def _policy_ack_facts(store: GuardStore, policy_bundle: dict[str, object]) -> dict[str, object]:
    """The facts the native runtime checks the policy bundle acknowledgement against."""

    try:
        device_id: str | None = str(store.get_device_metadata()["installation_id"])
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        device_id = None
    return {
        "acknowledgement": _sync_payload_dict(store, "policy_bundle_ack"),
        "bundle_hash": _optional_string(policy_bundle.get("bundleHash")),
        "bundle_version": _optional_string(policy_bundle.get("bundleVersion")),
        "device_id": device_id,
    }


def _build_runtime_device_context(store: GuardStore) -> dict[str, object]:
    metadata = store.get_device_metadata()
    return {
        "installation_id": metadata["installation_id"],
        "device_label": metadata["device_label"],
        "local_registered": True,
    }


def _build_latest_connect_state(store: GuardStore, now: str) -> dict[str, object] | None:
    state = store.get_effective_guard_connect_state(now=now)
    if state is None:
        return None
    return {
        "request_id": _optional_string(state.get("request_id")),
        "status": _optional_string(state.get("status")),
        "milestone": _optional_string(state.get("milestone")),
        "reason": _optional_string(state.get("reason")),
        "created_at": _optional_string(state.get("created_at")),
        "updated_at": _optional_string(state.get("updated_at")),
        "expires_at": _optional_string(state.get("expires_at")),
        "completed_at": _optional_string(state.get("completed_at")),
        "proof": _connect_state_proof(state.get("proof")),
    }


def _connect_state_proof(value: object) -> dict[str, object]:
    source = value if isinstance(value, Mapping) else {}
    return {
        "pairing_completed_at": _optional_string(source.get("pairing_completed_at")),
        "first_synced_at": _optional_string(source.get("first_synced_at")),
        "receipts_stored": _non_negative_int(source.get("receipts_stored")),
        "inventory_items": _non_negative_int(source.get("inventory_items")),
        "runtime_session_id": _optional_string(source.get("runtime_session_id")),
        "runtime_session_synced_at": _optional_string(source.get("runtime_session_synced_at")),
    }


def _runtime_headline(
    store: GuardStore,
    *,
    pending_count: int,
    runtime_state_present: bool,
    protection_state: str,
) -> dict[str, object]:
    """Ask the native runtime for the snapshot headline.

    The headline is display only, so an unavailable runtime still reports
    setup and a waiting decision, and otherwise reports degraded rather than
    claiming protection.
    """
    from .native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    try:
        reply = native_runner_authority(
            "runtime_headline",
            {
                "pending_count": pending_count,
                "runtime_state_present": runtime_state_present,
                "protection_state": protection_state,
            },
            guard_home=store.guard_home,
        )
    except NativeRunnerAuthorityError as error:
        _LOGGER.debug("runtime headline unavailable: %s", error)
        reply = None
    if isinstance(reply, dict) and all(isinstance(reply.get(key), str) for key in _HEADLINE_UNAVAILABLE):
        return {key: reply[key] for key in _HEADLINE_UNAVAILABLE}
    if not runtime_state_present:
        return dict(_HEADLINE_SETUP)
    if pending_count > 0:
        return dict(_HEADLINE_NEEDS_DECISION)
    return dict(_HEADLINE_UNAVAILABLE)


def bulk_allow_read_only_once(
    *,
    store: GuardStore,
    request_ids: Sequence[str],
    approval_gate_input: ApprovalGateInput | None,
    now: str | None = None,
) -> dict[str, object]:
    from .approval_gate import public_config
    from .store_base import _canonical_utc_timestamp

    resolved_at = _canonical_utc_timestamp(now or _now())
    gate = public_config(store.guard_home, now=resolved_at)
    if not gate.enabled or not gate.configured:
        raise ValueError("bulk_approve_gate_required")

    if len(request_ids) == 0:
        return {
            "resolved_count": 0,
            "failed": [],
            "resolution_summary": "0 actions approved once.",
        }

    bulk_resolution_action = "allow"
    bulk_resolution_scope = "artifact"
    resolved_count = 0
    failed: list[dict[str, str]] = []
    eligible_ids: list[str] = []
    candidates: list[tuple[str, Mapping[str, object] | None]] = []
    for request_id in request_ids:
        if not isinstance(request_id, str) or not request_id.strip():
            failed.append({"request_id": str(request_id), "error": "invalid_request_id"})
            continue
        normalized_id = request_id.strip()
        candidates.append((normalized_id, store.get_approval_request(normalized_id)))
    from .native_approval_bulk_eligibility import native_bulk_allow_once_eligibility

    verdicts = iter(
        native_bulk_allow_once_eligibility(
            [request for _, request in candidates if request is not None],
            guard_home=store.guard_home,
        )
    )
    for normalized_id, request in candidates:
        if request is None or not next(verdicts):
            failed.append({"request_id": normalized_id, "error": "ineligible"})
            continue
        eligible_ids.append(normalized_id)

    if not eligible_ids:
        return {
            "resolved_count": 0,
            "failed": failed,
            "resolution_summary": "0 actions approved once.",
        }

    bulk_subject = f"approval-request-batch:{uuid.uuid5(uuid.NAMESPACE_URL, chr(0).join(sorted(eligible_ids))).hex}"
    bulk_gate_grant = require_approval_decision(
        store.guard_home,
        action=bulk_resolution_action,
        scope=bulk_resolution_scope,
        subject=bulk_subject,
        approval_gate_input=approval_gate_input,
        now=resolved_at,
    )

    scope_unavailable = False
    for index, normalized_id in enumerate(eligible_ids):
        try:
            apply_approval_resolution(
                store=store,
                request_id=normalized_id,
                action=bulk_resolution_action,
                scope=bulk_resolution_scope,
                workspace=None,
                reason="bulk approve once",
                now=resolved_at,
                return_queue_result=False,
                resolve_scope_matches=False,
                approval_gate_grant=bulk_gate_grant,
                approval_gate_subject=bulk_subject,
                persist_policy=False,
            )
            resolved_count += 1
        except ApprovalScopeUnavailableError as error:
            # A resident outage affects every remaining row; stop instead of retrying each one.
            failed.extend({"request_id": remaining, "error": str(error)} for remaining in eligible_ids[index:])
            scope_unavailable = True
            break
        except (ApprovalRequestNotFoundError, ApprovalRequestAlreadyResolvedError, ValueError) as error:
            failed.append({"request_id": normalized_id, "error": str(error)})

    result: dict[str, object] = {
        "resolved_count": resolved_count,
        "failed": failed,
        "resolution_summary": f"{resolved_count} action{'s' if resolved_count != 1 else ''} approved once.",
    }
    if scope_unavailable:
        result["error"] = APPROVAL_SCOPE_UNAVAILABLE
    return result


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


_non_negative_int = coerce_non_negative_int


def _queue_risk_summary(queued: list[dict[str, object]]) -> str:
    signals: list[str] = []
    for item in queued:
        for signal in _string_list(item.get("risk_signals")):
            if signal not in signals:
                signals.append(signal)
    if len(signals) == 0:
        return "No obvious secret-access or network signal was detected."
    if len(signals) == 1:
        return f"Risk signal: {signals[0]}."
    return f"Risk signals: {signals[0]}, {signals[1]}."
