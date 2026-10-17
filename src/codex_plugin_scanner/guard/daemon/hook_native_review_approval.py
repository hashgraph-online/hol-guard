"""Queue native PreToolUse pauses while Rust remains the semantic authority."""

from __future__ import annotations

import logging
import sqlite3
import uuid
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ..approval_link_output import native_review_reason
from ..models import GuardApprovalRequest
from ..native_decision_receipt import validate_native_decision_receipt
from ..native_hook_adapter import NativeHookAdapterError
from ..runtime.actions import normalize_harness_payload
from .hook_fail_closed import canonical_harness, render_accepted_allow, render_pre_tool, render_pre_tool_review
from .hook_native_exact_action import native_exact_action, native_review_binding
from .hook_native_local_cli import native_local_cli_grant_response
from .hook_native_package_review import native_package_review_response
from .hook_native_review_binding import (
    native_review_claimed_allow,
    native_review_matching_allow,
    native_review_matching_block,
    native_review_policy_binding,
)
from .hook_native_saved_approval import (
    EXACT_ACTION_CONTEXT_TOKEN_KEY,
    EXACT_ACTION_IDENTITY_KIND_KEY,
    ONCE_ONLY_REASON_KEY,
    TOKEN_UNSET,
    TokenUnset,
    native_saved_review_response,
)
from .hook_request_parsing import pre_tool_command, pre_tool_input
from .native_review_allow_hint import native_review_extension_allow_hint
from .native_review_connector import connector_agent_reason, native_review_setup_connector, raise_connector_setup_notice
from .native_review_records import native_review_approval_center_url, record_silent_native_review_event

if TYPE_CHECKING:
    from ..local_cli_hook import SetupConnector
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)


def pause_native_pre_tool_for_approval(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
    home_dir: Path | None = None,
    deadline: float | None = None,
    claim_saved_approval: bool = True,
    claimed_saved_allow_hash: str | None = None,
    claimed_approval_request_id: str | None = None,
) -> dict[str, object]:
    try:
        native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
    except ValueError:
        failed = dict(native_result)
        failed.update(
            decision="deny",
            minimum_action="block",
            policy_action="block",
            reason_code="native_review_policy_binding_invalid",
            reason="HOL Guard could not bind this review to its native policy.",
        )
        return render_pre_tool(harness, failed, guard_home=guard_home)
    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    identity = native_review_binding(harness, payload, native_result, native_receipt, workspace, guard_home)
    # Custom-extension and saved exact-action blocks win over any allow or pending once approval.
    custom = native_local_cli_grant_response(
        store,
        harness=harness,
        payload=payload,
        native_result=native_result,
        workspace=workspace,
        home_dir=home_dir,
    )
    if custom is not None and custom[0]:
        return custom[1]
    # Derive the exact-action token once: the saved-decision lookup and the queued
    # request must bind the identical value, and each derivation re-reads operands
    # and repeats resident launch-identity round trips.
    exact_token, once_only_reason = native_exact_action(
        harness=harness,
        tool_name=tool_name,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
    )
    saved = native_saved_review_response(
        store,
        harness=harness,
        tool_name=tool_name,
        artifact_id=_native_review_artifact_id(harness, tool_name),
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        home_dir=home_dir,
        precomputed_token=exact_token,
        guard_home=guard_home,
    )
    if saved is not None:
        return saved
    if custom is not None:
        return custom[1]
    if native_review_matching_block(
        store,
        harness=harness,
        tool_name=tool_name,
        artifact_id=_native_review_artifact_id(harness, tool_name),
        launch_target=launch_target,
        workspace=workspace,
        identity=identity,
    ):
        blocked = dict(native_result)
        blocked.update(
            decision="deny",
            minimum_action="block",
            policy_action="block",
            reason_code="native_review_user_block",
            reason=(
                "The user chose Keep blocked for this action. Do not retry it; continue with a permitted alternative."
            ),
        )
        response = render_pre_tool(harness, blocked, guard_home=guard_home, deadline=deadline)
        response["prompted"] = False
        response["approval_reuse_status"] = "blocked"
        return response
    if claimed_saved_allow_hash is not None and native_review_claimed_allow(
        store,
        harness=harness,
        artifact_id=_native_review_artifact_id(harness, tool_name),
        workspace=workspace,
        identity=identity,
        claimed_saved_allow_hash=claimed_saved_allow_hash,
        claimed_approval_request_id=claimed_approval_request_id,
        claim_saved_approval=claim_saved_approval,
    ):
        allowed = dict(native_result)
        allowed["decision"] = "allow"
        allowed["minimum_action"] = "allow"
        allowed["policy_action"] = "allow"
        return render_accepted_allow(harness, allowed, guard_home=guard_home, deadline=deadline)
    if claim_saved_approval and native_review_matching_allow(
        store,
        harness=harness,
        tool_name=tool_name,
        artifact_id=_native_review_artifact_id(harness, tool_name),
        launch_target=launch_target,
        workspace=workspace,
        identity=identity,
    ):
        allowed = dict(native_result)
        allowed["decision"] = "allow"
        allowed["minimum_action"] = "allow"
        allowed["policy_action"] = "allow"
        return render_accepted_allow(harness, allowed, guard_home=guard_home, deadline=deadline)
    settled = native_package_review_response(
        store,
        harness=harness,
        payload=payload,
        native_result=native_result,
        workspace=workspace,
        guard_home=guard_home,
        home_dir=home_dir,
        deadline=deadline,
    )
    if settled is not None:
        return settled
    from ..blocked_request_mode import asks_for_approval, safe_alternative_reason
    from ..config import load_guard_config

    try:
        ask = asks_for_approval(load_guard_config(guard_home, workspace=workspace))
    except (OSError, RuntimeError, TypeError, ValueError):
        ask = False
    approval_center_url = native_review_approval_center_url(store)
    connector = native_review_setup_connector(
        store, payload=payload, native_result=native_result, workspace=workspace, home_dir=home_dir
    )
    # Approving a row bound to neither the retry nor an exact-action Always
    # cannot let the agent run the action, so the reason never sends the user there.
    approval_can_unblock = identity is not None or exact_token is not None
    # The row keeps the native reason as evidence; only the agent text changes.
    setup_reason = None if connector is None else connector_agent_reason(connector, ask=ask and approval_can_unblock)
    if not ask or (identity is None and exact_token is None):
        # The agent stays on the silent block. The inbox row is a separate record.
        queued = queue_native_pre_tool_review(
            store,
            harness=harness,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            guard_home=guard_home,
            home_dir=home_dir,
            deadline=deadline,
            exact_token=exact_token,
            once_only_reason=once_only_reason,
            approval_center_url=approval_center_url,
            review_binding=identity,
            connector=connector,
        )
        if queued is None:
            _LOGGER.warning("Silent review blocked without an inbox row for %s", harness)
        else:
            record_silent_native_review_event(store, queued)
        reason = setup_reason or safe_alternative_reason(
            str(native_result.get("reason") or "HOL Guard blocked this action."),
            reason_code=str(native_result.get("reason_code") or "") or "unknown",
            approval_queued=queued is not None,
            # The queued row is stored with this same binding; without one a
            # one-time approval cannot match the agent's retry.
            retry_reuses_approval=identity is not None,
            exact_action_allowable=exact_token is not None,
        )
        # A setup review never links in the default mode.
        link = approval_can_unblock and (ask or setup_reason is None)
        raw_url = queued.get("approval_url") if queued is not None and link else None
        if isinstance(raw_url, str) and raw_url.strip():
            # The agent passes the link on, so the user can open the queued row.
            reason = native_review_reason(canonical_harness(harness), reason, raw_url.strip(), guard_home=guard_home)
        blocked = dict(native_result)
        blocked.update(decision="deny", minimum_action="block", policy_action="block", reason=reason)
        response = render_pre_tool(harness, blocked, guard_home=guard_home, deadline=deadline)
        response["prompted"] = False
        response["blocked_request_mode"] = "safe-alternative"
        return response

    queued = queue_native_pre_tool_review(
        store,
        harness=harness,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        guard_home=guard_home,
        home_dir=home_dir,
        deadline=deadline,
        exact_token=exact_token,
        once_only_reason=once_only_reason,
        approval_center_url=approval_center_url,
        review_binding=identity,
        connector=connector,
    )
    if queued is None:
        failed = dict(native_result)
        failed["decision"] = "deny"
        failed["minimum_action"] = "block"
        failed["policy_action"] = "block"
        failed["reason_code"] = "native_review_queue_failed"
        failed["reason"] = "HOL Guard could not record this review for approval."
        return render_pre_tool(harness, failed, guard_home=guard_home, deadline=deadline)
    response = render_pre_tool_review(
        harness,
        native_result if setup_reason is None else {**native_result, "reason": setup_reason},
        approval=queued,
        guard_home=guard_home,
        deadline=deadline,
    )
    response["prompted"] = True
    response["approval_center_url"] = approval_center_url
    return response


def queue_native_pre_tool_review(
    store: object,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
    home_dir: Path | None = None,
    deadline: float | None = None,
    exact_token: str | None | TokenUnset = TOKEN_UNSET,
    once_only_reason: str | None = None,
    approval_center_url: str | None = None,
    review_binding: str | None | TokenUnset = TOKEN_UNSET,
    connector: SetupConnector | None = None,
) -> dict[str, object] | None:
    try:
        native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
    except ValueError:
        return None
    persist = getattr(store, "add_approval_request", None)
    lookup = getattr(store, "get_approval_request", None)
    if not callable(persist) or not callable(lookup):
        return None
    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    request_id = uuid.uuid4().hex
    artifact_id = _native_review_artifact_id(harness, tool_name)
    if approval_center_url is None:
        approval_center_url = native_review_approval_center_url(store)
    approval_url = f"{approval_center_url}/requests/{request_id}"
    reason = str(native_result.get("reason") or "HOL Guard requires review before this action can execute.")
    # The pause path already asked the resident for this binding. Asking again
    # repeats a resident round trip that can exhaust the hook deadline on Windows.
    binding = (
        native_review_binding(harness, payload, native_result, native_receipt, workspace, guard_home)
        if isinstance(review_binding, TokenUnset)
        else review_binding
    )
    try:
        action_envelope = _native_review_action_envelope(
            harness=harness,
            payload=payload,
            native_receipt=native_receipt,
            workspace=workspace,
            guard_home=guard_home,
            home_dir=home_dir,
            deadline=deadline,
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as error:
        # Never make an action approvable when its details could not be safely presented.
        # Exception messages can contain private tool input; log only the error class and, for
        # native adapter outages, its fixed reason code (unavailable, deadline, size).
        reason = error.code if isinstance(error, NativeHookAdapterError) else type(error).__name__
        _LOGGER.warning("Native review presentation failed for %s (%s)", request_id, reason)
        return None
    if action_envelope is None:
        _LOGGER.warning("Native review presentation failed for %s (ValueError)", request_id)
        return None
    # Offer an exact-action Always only when the action binds to a stable token.
    if isinstance(exact_token, TokenUnset):
        exact_token, once_only_reason = native_exact_action(
            harness=harness,
            tool_name=tool_name,
            payload=payload,
            native_result=native_result,
            native_receipt=native_receipt,
            workspace=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )
    if exact_token is not None:
        action_envelope[EXACT_ACTION_CONTEXT_TOKEN_KEY] = exact_token
        if pre_tool_command(payload) is None:
            action_envelope[EXACT_ACTION_IDENTITY_KIND_KEY] = "tool-target"
    elif once_only_reason is not None:
        action_envelope[ONCE_ONLY_REASON_KEY] = once_only_reason
    request = GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=artifact_id,
        artifact_name=tool_name,
        artifact_hash=binding or request_id,
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("native_pre_tool",),
        source_scope="project" if workspace is not None else "harness",
        config_path=str(workspace if workspace is not None else guard_home),
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=approval_url,
        workspace=str(workspace) if workspace is not None else None,
        artifact_type="tool_call",
        launch_target=launch_target,
        risk_summary=reason,
        action_envelope_json=action_envelope,
        raw_command_text=pre_tool_command(payload),
        queue_group_id=None if connector is None else connector.queue_group_id,
        extension_allow_hint=native_review_extension_allow_hint(
            store,
            payload=payload,
            native_result=native_result,
            workspace=workspace,
            home_dir=home_dir,
            deadline=deadline,
        ),
    )
    try:
        persisted_id = persist(request, datetime.now(tz=timezone.utc).isoformat())
        stored = lookup(persisted_id)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None
    raise_connector_setup_notice(store, stored, connector)
    return stored if isinstance(stored, dict) else None


def _native_review_artifact_id(harness: str, tool_name: str) -> str:
    return f"{harness}:native-pretool:{tool_name}"


def record_claude_permission_notice_for_native_review(
    store: GuardStore,
    *,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    native_receipt: Mapping[str, object] | None,
    workspace: Path | None,
    guard_home: Path,
) -> None:
    """Persist the Claude permission-prompt notice for a queued native review."""
    from ..cli.commands_support_hook_state import _record_claude_permission_notice
    from ..models import GuardArtifact

    tool_name = _native_review_tool_name(payload)
    command = pre_tool_command(payload)
    artifact_id = _native_review_artifact_id(harness, tool_name)
    binding = native_review_binding(harness, payload, native_result, native_receipt, workspace, guard_home)
    metadata: dict[str, object] = {"raw_command_text": command} if command else {}
    artifact = GuardArtifact(
        artifact_id=artifact_id,
        name=tool_name,
        harness=harness,
        artifact_type="tool_call",
        source_scope="project" if workspace is not None else "harness",
        config_path=str(workspace if workspace is not None else guard_home),
        command=command,
        metadata=metadata,
    )
    _record_claude_permission_notice(
        store=store,
        payload=dict(payload),
        reason=str(native_result.get("reason") or "HOL Guard requires review before this action can execute."),
        artifact=artifact,
        artifact_hash=binding or artifact_id,
    )


def _native_review_action_envelope(
    *,
    harness: str,
    payload: Mapping[str, object],
    native_receipt: Mapping[str, object] | None = None,
    workspace: Path | None,
    guard_home: Path | None = None,
    home_dir: Path | None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """Store the canonical redacted envelope used by live revalidation."""

    try:
        envelope = (
            normalize_harness_payload(
                harness,
                "PreToolUse",
                dict(payload),
                workspace=workspace,
                home_dir=home_dir,
                guard_home=guard_home,
                deadline=deadline,
            )
            .with_pre_execution_result("review")
            .to_dict()
        )
    except ValueError:
        return None
    validated = validate_native_decision_receipt(native_receipt)
    if validated is None or "origin_authentication" not in validated:
        return envelope
    # Keep only the validated aggregate receipt. Never carry raw hook input
    # through the presentation envelope, and do not alias nested mappings.
    envelope["native_origin_receipt"] = deepcopy(validated)
    return envelope


def _native_review_tool_name(payload: Mapping[str, object]) -> str:
    for key in ("tool_name", "toolName", "tool"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "tool"


def _native_review_launch_target(payload: Mapping[str, object]) -> str:
    command = pre_tool_command(payload)
    if command is not None:
        return command
    tool_input = pre_tool_input(payload)
    if tool_input is not None:
        for key in ("url", "path", "file_path", "target"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return f"tool:{_native_review_tool_name(payload)}"


__all__ = [
    "pause_native_pre_tool_for_approval",
    "queue_native_pre_tool_review",
    "record_claude_permission_notice_for_native_review",
]
