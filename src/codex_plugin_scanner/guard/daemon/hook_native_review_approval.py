"""Queue native PreToolUse pauses while Rust remains the semantic authority."""

from __future__ import annotations

import logging
import sqlite3
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ..models import GuardApprovalRequest
from ..native_hook_adapter import NativeHookAdapterError, native_review_request
from ..native_hook_authority_state import hook_authority_integrity_key
from .hook_fail_closed import (
    canonical_harness,
    render_accepted_allow,
    render_pre_tool,
    render_pre_tool_review,
    render_silent_review_block,
)
from .hook_native_exact_action import native_review_evidence
from .hook_native_package_review import native_package_review_response
from .hook_native_review_binding import (
    native_review_claimed_allow,
    native_review_matching_allow,
    native_review_matching_block,
    native_review_policy_binding,
)
from .hook_native_saved_approval import native_saved_decision_response
from .hook_request_parsing import native_review_launch_target as _native_review_launch_target
from .hook_request_parsing import native_review_tool_name as _native_review_tool_name
from .hook_request_parsing import pre_tool_command
from .native_review_allow_hint import native_review_hint
from .native_review_connector import (
    connector_agent_reason,
    connector_is_local,
    native_review_setup_connector,
    raise_connector_setup_notice,
    record_native_review_connector_context,
)
from .native_review_records import native_review_approval_center_url, record_silent_native_review_event

if TYPE_CHECKING:
    from ..local_cli_hook import SetupConnector
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)


def _policy_binding_failed(harness: str, native_result: Mapping[str, object], guard_home: Path) -> dict[str, object]:
    failed = dict(native_result)
    failed.update(
        decision="deny",
        minimum_action="block",
        policy_action="block",
        reason_code="native_review_policy_binding_invalid",
        reason="HOL Guard could not bind this review to its native policy.",
    )
    return render_pre_tool(harness, failed, guard_home=guard_home)


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
    local_cli_rule: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Answer a native review; ``local_cli_rule`` is the edge's custom extension rule."""
    try:
        native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
    except ValueError:
        return _policy_binding_failed(harness, native_result, guard_home)
    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    # Custom-extension and saved exact-action blocks win over any allow or pending once approval.
    custom = None if local_cli_rule is None else cast("dict[str, object]", local_cli_rule["harness_response"])
    if local_cli_rule is not None and local_cli_rule["blocked"] is True:
        return cast("dict[str, object]", custom)
    # A matching custom grant never uses the evidence below, so it settles first.
    # One resident ask re-checks the receipt's policy binding and answers both
    # the retry binding and the exact-action token. The saved-decision lookup
    # and the queued request must bind the identical token, so it is derived once.
    valid, identity, exact_token, once_only_reason = native_review_evidence(
        harness=harness,
        payload=payload,
        native_result=native_result,
        native_receipt=native_receipt,
        workspace=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
    )
    if not valid:
        return _policy_binding_failed(harness, native_result, guard_home)
    saved = native_saved_decision_response(
        store,
        harness=harness,
        token=exact_token,
        artifact_id=_native_review_artifact_id(harness, tool_name),
        native_result=native_result,
        workspace=workspace,
    )
    if saved is not None:
        return saved
    if custom is not None:
        return custom
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
    from ..blocked_request_mode import asks_for_approval
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
    if connector is None or (connector_is_local(connector) and identity is None and exact_token is not None):
        # Only an exact-action Always allow can release a local row without a retry binding;
        # the ordinary review text says so.
        setup_reason = None
    else:
        setup_reason = connector_agent_reason(
            connector, ask=ask and approval_can_unblock, approvable=identity is not None
        )
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
            policy_binding_verified=True,
        )
        if queued is None:
            _LOGGER.warning("Silent review blocked without an inbox row for %s", harness)
        else:
            record_silent_native_review_event(store, queued)
        request_id, approval_url = (queued.get("request_id"), queued.get("approval_url")) if queued else (None, None)
        inputs = {
            "harness": harness,
            "result": dict(native_result),
            # The resident drops the setup text when the review never reached the inbox.
            "setup_reason": setup_reason,
            "queued": queued is not None,
            "request_id": request_id if isinstance(request_id, str) else None,
            "approval_url": approval_url if isinstance(approval_url, str) else None,
            "ask": ask,
            # The queued row is stored with this same binding; without one a
            # one-time approval cannot match the agent's retry.
            "retry_reuses_approval": identity is not None,
            "exact_action_allowable": exact_token is not None,
            "connector_is_local": connector_is_local(connector),
            "guard_home": str(guard_home),
            "home_dir": str(home_dir or Path.home()),
        }
        return render_silent_review_block(harness, inputs, guard_home=guard_home, deadline=deadline)

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
        policy_binding_verified=True,
        claude_notice=canonical_harness(harness) == "claude-code",
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
    exact_token: str | None,
    review_binding: str | None,
    home_dir: Path | None = None,
    deadline: float | None = None,
    once_only_reason: str | None = None,
    approval_center_url: str | None = None,
    connector: SetupConnector | None = None,
    bound_bash: Mapping[str, object] | None = None,
    claude_notice: bool = False,
    policy_binding_verified: bool = False,
) -> dict[str, object] | None:
    if not policy_binding_verified:
        try:
            native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
        except ValueError:
            return None
    persist = getattr(store, "add_approval_request", None)
    lookup = getattr(store, "get_approval_request", None)
    if not callable(persist) or not callable(lookup):
        return None
    if bound_bash is not None:
        from .native_review_bound_bash import valid_bound_bash_review

        if not valid_bound_bash_review(
            bound_bash,
            harness=harness,
            exact_token=exact_token,
            review_binding=review_binding,
            decision=native_result,
            native_receipt=native_receipt,
        ):
            return None
    request_id = uuid.uuid4().hex
    review = {
        "result": dict(native_result),
        "native_receipt": dict(native_receipt) if native_receipt is not None else None,
        "request_id": request_id,
        "approval_center_url": (
            native_review_approval_center_url(store) if approval_center_url is None else approval_center_url
        ),
        "guard_home": str(guard_home),
        "review_binding": review_binding,
        "exact_token": exact_token,
        "once_only_reason": once_only_reason,
        "queue_group_id": None if connector is None else connector.queue_group_id,
        "bound_bash": (
            None
            if bound_bash is None
            else {"subject": bound_bash["subject"], "review_lineage": bound_bash["review_lineage"]}
        ),
    }
    try:
        fields = native_review_request(
            harness,
            payload,
            review,
            workspace=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
            deadline=deadline,
        )
        request = GuardApprovalRequest(
            **cast("dict[str, Any]", {key: value for key, value in fields.items() if key != "changed_fields"}),
            changed_fields=tuple(cast("list[str]", fields["changed_fields"])),
            extension_allow_hint=native_review_hint(
                store, payload, native_result, workspace, home_dir, deadline, connector
            ),
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as error:
        # Never make an action approvable when its details could not be safely presented.
        # Exception messages can contain private tool input; log only the error class and, for
        # native adapter outages, its fixed reason code (unavailable, deadline, size).
        reason = error.code if isinstance(error, NativeHookAdapterError) else type(error).__name__
        _LOGGER.warning("Native review presentation failed for %s (%s)", request_id, reason)
        return None
    now = datetime.now(tz=timezone.utc).isoformat()
    # A prompted Claude review also gets the permission notice its
    # PermissionRequest hook answers from; the resident builds and signs it in
    # the same store write.
    claude_review = (
        _claude_review_notice(store, harness, payload, native_result, review_binding, request, deadline)
        if claude_notice
        else None
    )
    try:
        stored = lookup(_persist_review(persist, request, now, claude_review))
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None
    if connector is not None and isinstance(stored, dict):
        record_native_review_connector_context(
            store,
            connector=connector,
            native_result=native_result,
            stored=stored,
            harness=harness,
            workspace=workspace,
            deadline=deadline,
        )
    raise_connector_setup_notice(store, stored, connector)
    return stored if isinstance(stored, dict) else None


def _persist_review(
    persist: Callable[..., object],
    request: GuardApprovalRequest,
    now: str,
    claude_review: dict[str, object] | None,
) -> object:
    if claude_review is None:
        return persist(request, now)
    try:
        return persist(request, now, claude_review=claude_review)
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        # The notice is best effort: a combined write the resident refuses
        # (too large, older resident) still queues the review.
        return persist(request, now)


def _native_review_artifact_id(harness: str, tool_name: str) -> str:
    return f"{harness}:native-pretool:{tool_name}"


def _claude_review_notice(
    store: object,
    harness: str,
    payload: Mapping[str, object],
    native_result: Mapping[str, object],
    binding: str | None,
    request: GuardApprovalRequest,
    deadline: float | None,
) -> dict[str, object] | None:
    """The facts the resident needs to sign a Claude review's notice, or ``None``.

    The notice is best effort, as the retired Python notice was: without an
    integrity key, or once reading it leaves too little of the hook deadline
    for the queue write, the review still queues and the hook falls back to
    its ordinary prompt. The key goes in the store request's top-level
    ``integrity_key_b64`` and ``integrity_key_id`` args, which the request
    digest never covers. The hook payload carries only what the notice reads,
    so the command is not copied in full a second time.
    """

    if not _notice_time_left(deadline):
        return None
    key = hook_authority_integrity_key(cast("GuardStore", store), create_key=True)
    if key is None or not _notice_time_left(deadline):
        return None
    hook_payload = {name: payload[name] for name in _NOTICE_PAYLOAD_FIELDS if name in payload}
    command = pre_tool_command(payload)
    if command:
        hook_payload["tool_input"] = {"command": command}
    return {
        "review": {
            "harness": harness,
            "hook_payload": hook_payload,
            "reason": native_result.get("reason"),
            "review_binding": binding,
            "config_path": request.config_path,
            "source_scope": request.source_scope,
        },
        **key,
    }


# What the resident's notice reads from the hook payload: the session and the
# tool name fields (`TOOL_NAME_FIELDS`); the command goes under `tool_input`.
_NOTICE_PAYLOAD_FIELDS = ("session_id", "tool_name", "toolName", "tool")
# Below this much of the hook deadline the notice is dropped, so the key read
# never costs the review its queue write.
_NOTICE_DEADLINE_MARGIN_SECONDS = 1.0


def _notice_time_left(deadline: float | None) -> bool:
    return deadline is None or deadline - time.monotonic() > _NOTICE_DEADLINE_MARGIN_SECONDS


__all__ = [
    "pause_native_pre_tool_for_approval",
    "queue_native_pre_tool_review",
]
