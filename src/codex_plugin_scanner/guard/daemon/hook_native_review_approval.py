"""Queue native PreToolUse pauses while Rust remains the semantic authority."""

from __future__ import annotations

import logging
import sqlite3
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, cast

from ..live_process_identity import CODEX_BROWSER_WAIT_PROCESS_KEY, CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY
from ..native_guard_store import NativeGuardStoreUnavailable
from ..native_hook_adapter import NativeHookAdapterError, native_review_query
from ..native_hook_authority_state import hook_authority_integrity_key
from .hook_fail_closed import (
    canonical_harness,
    render_accepted_allow,
    render_pre_tool,
    render_pre_tool_review,
    render_silent_review_block,
)
from .hook_native_exact_action import review_evidence_parts
from .hook_native_package_review import native_package_review_response
from .hook_native_review_binding import native_review_policy_binding, native_review_settle
from .hook_native_saved_approval import native_exact_command_block_response, native_saved_decision_response
from .hook_request_parsing import native_review_launch_target as _native_review_launch_target
from .hook_request_parsing import native_review_tool_name as _native_review_tool_name
from .hook_request_parsing import pre_tool_command
from .native_review_allow_hint import native_review_hint_ask
from .native_review_connector import native_review_connector_lookup, raise_connector_setup_notice
from .native_review_records import native_review_approval_center_url

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)
# An older resident renders the silent block only from facts the daemon names,
# including the setup text it no longer looks up; a call without them is
# refused there and the review never reaches the inbox. The current resident
# renders from its own lookup and ignores these.
_OLDER_RESIDENT_SETUP: dict[str, object] = {"setup_reason": None, "connector_is_local": False}


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
    review_evidence: Mapping[str, object] | None = None,
    exact_command_block: object = None,
) -> dict[str, object]:
    """Answer a native review from the edge's custom extension rule and review evidence."""
    launch_target = _native_review_launch_target(payload)
    tool_name = _native_review_tool_name(payload)
    # Custom-extension and saved exact-action blocks win over any allow or pending once approval.
    custom = None if local_cli_rule is None else cast("dict[str, object]", local_cli_rule["harness_response"])
    if local_cli_rule is not None and local_cli_rule["blocked"] is True:
        return cast("dict[str, object]", custom)
    # A custom block denies whatever the policy binding holds, so it settles
    # before the binding is checked. The edge answered the receipt's policy
    # binding, the retry binding and the exact-action token in the same round
    # trip; the saved-decision lookup and the queued request bind that one
    # token. Missing evidence fails closed.
    evidence = review_evidence_parts(review_evidence)
    if evidence is None:
        _LOGGER.warning("Native review for %s arrived without the edge's review evidence", harness)
        return _policy_binding_failed(harness, native_result, guard_home)
    valid, identity, exact_token, once_only_reason = evidence
    if not valid:
        return _policy_binding_failed(harness, native_result, guard_home)
    # A saved block on the exact command, such as a Guard Cloud policy rule,
    # wins over an exact-action allow or a pending once approval.
    command_block = native_exact_command_block_response(
        store,
        harness=harness,
        command=pre_tool_command(payload),
        native_result=native_result,
        workspace=workspace,
        edge_hint=exact_command_block,
    )
    if command_block is not None:
        return command_block
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
    # The Keep blocked check, a claimed once-approval and the approve-once
    # spend run in one resident call.
    reuse = native_review_settle(
        store,
        harness=harness,
        tool_name=tool_name,
        artifact_id=_native_review_artifact_id(harness, tool_name),
        launch_target=launch_target,
        workspace=workspace,
        identity=identity,
        spend=claim_saved_approval,
        claimed_saved_allow_hash=claimed_saved_allow_hash,
        claimed_approval_request_id=claimed_approval_request_id,
    )
    if reuse == "blocked":
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
    if reuse == "allowed":
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
    # The queue call looks up the connector a non-recognition review waits on
    # and answers the agent with its setup text; the row keeps the native
    # reason as evidence.
    connector_lookup = native_review_connector_lookup(
        payload=payload, native_result=native_result, workspace=workspace, home_dir=home_dir
    )
    if not ask or (identity is None and exact_token is None):
        # The agent stays on the silent block. The inbox row is a separate record.
        facts = {"ask": ask, "home_dir": str(home_dir or Path.home())}
        # The queued row is stored with this same binding; without one a
        # one-time approval cannot match the agent's retry.
        bound = {"retry_reuses_approval": identity is not None, "exact_action_allowable": exact_token is not None}
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
            connector_lookup=connector_lookup,
            policy_binding_verified=True,
            silent=True,
            respond={"silent_review_block": {**facts, **bound, **_OLDER_RESIDENT_SETUP}},
        )
        if queued is None:
            _LOGGER.warning("Silent review blocked without an inbox row for %s", harness)
        block = queued.pop("hook_response", None) if queued else None
        if isinstance(block, dict):
            return block
        request_id, approval_url = (queued.get("request_id"), queued.get("approval_url")) if queued else (None, None)
        setup = _connector_setup(queued)
        inputs = {
            "harness": harness,
            "result": dict(native_result),
            "queued": queued is not None,
            "request_id": request_id if isinstance(request_id, str) else None,
            "approval_url": approval_url if isinstance(approval_url, str) else None,
            "guard_home": str(guard_home),
            # The resident drops the setup text when the review never reached the inbox.
            "setup_reason": setup.get("setup_reason"),
            "connector_is_local": setup.get("is_local") is True,
            **bound,
            **facts,
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
        connector_lookup=connector_lookup,
        policy_binding_verified=True,
        claude_notice=canonical_harness(harness) == "claude-code",
        codex_live_wait=canonical_harness(harness) == "codex",
        respond={"paused_review": {}},
    )
    if queued is None:
        failed = dict(native_result)
        failed["decision"] = "deny"
        failed["minimum_action"] = "block"
        failed["policy_action"] = "block"
        failed["reason_code"] = "native_review_queue_failed"
        failed["reason"] = "HOL Guard could not record this review for approval."
        return render_pre_tool(harness, failed, guard_home=guard_home, deadline=deadline)
    # The queue call renders the paused review with the row it stored; a row
    # read back separately carries none.
    response = queued.pop("hook_response", None)
    if not isinstance(response, dict):
        setup_reason = _connector_setup(queued).get("setup_reason")
        response = render_pre_tool_review(
            harness,
            native_result if not isinstance(setup_reason, str) else {**native_result, "reason": setup_reason},
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
    connector_lookup: dict[str, object] | None = None,
    bound_bash: Mapping[str, object] | None = None,
    claude_notice: bool = False,
    policy_binding_verified: bool = False,
    codex_live_wait: bool = False,
    silent: bool = False,
    respond: dict[str, object] | None = None,
) -> dict[str, object] | None:
    if not policy_binding_verified:
        try:
            native_review_policy_binding(harness=harness, native_result=native_result, verified_receipt=native_receipt)
        except ValueError:
            return None
    queue = getattr(store, "queue_native_review", None)
    if not callable(queue):
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
    live_wait = _codex_live_wait(payload, workspace) if codex_live_wait else None
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
        # A connector the queue call finds groups the row under its setup.
        "queue_group_id": None,
        "bound_bash": (
            None
            if bound_bash is None
            else {"subject": bound_bash["subject"], "review_lineage": bound_bash["review_lineage"]}
        ),
    }
    try:
        query = native_review_query(harness, payload, review, workspace=workspace, home_dir=home_dir)
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as error:
        # Never make an action approvable when its details could not be safely presented.
        # Exception messages can contain private tool input; log only the error class and, for
        # native adapter outages, its fixed reason code (unavailable, deadline, size).
        reason = error.code if isinstance(error, NativeHookAdapterError) else type(error).__name__
        _LOGGER.warning("Native review presentation failed for %s (%s)", request_id, reason)
        return None
    now = datetime.now(tz=timezone.utc).isoformat()
    try:
        # The resident looks up the connector a non-recognition review waits
        # on, builds the request from the query, decides its hint and queues it
        # in one store call. A waiting Codex hook's operation and resume
        # record, a prompted Claude review's permission notice, and a
        # connector-setup review's context are written with it.
        stored = queue(
            query,
            now,
            hint=native_review_hint_ask(deadline),
            silent=silent,
            claude_key=_claude_notice_key(store, deadline) if claude_notice else None,
            codex_live_wait=live_wait,
            respond=respond,
            connector_lookup=connector_lookup,
        )
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as error:
        # The action fails closed. Only the store's fixed reason code, never an
        # exception message that can carry tool input, reaches the log.
        reason = error.reason if isinstance(error, NativeGuardStoreUnavailable) else type(error).__name__
        _LOGGER.warning("Native review queue failed for %s (%s)", request_id, reason)
        return None
    raise_connector_setup_notice(store, stored)
    return stored if isinstance(stored, dict) else None


def _connector_setup(queued: object) -> Mapping[str, object]:
    """The connector the queue call found for the review, or nothing."""
    setup = queued.get("connector_setup") if isinstance(queued, dict) else None
    return cast(Mapping[str, object], setup) if isinstance(setup, dict) else {}


def _codex_live_wait(payload: Mapping[str, object], workspace: Path | None) -> dict[str, object] | None:
    """The waiting bridge's facts; the resident proves it live and builds the wait it links."""
    process = payload.get(CODEX_BROWSER_WAIT_PROCESS_KEY)
    timeout_seconds = payload.get(CODEX_BROWSER_WAIT_TIMEOUT_SECONDS_KEY)
    if process is None and timeout_seconds is None:
        return None
    return {
        "process": process,
        "timeout_seconds": timeout_seconds,
        "workspace": None if workspace is None else str(workspace),
    }


def _native_review_artifact_id(harness: str, tool_name: str) -> str:
    return f"{harness}:native-pretool:{tool_name}"


def _claude_notice_key(store: object, deadline: float | None) -> dict[str, str] | None:
    """The integrity key a prompted Claude review's notice is signed with, or ``None``.

    The notice is best effort, as the retired Python notice was: without an
    integrity key, or once reading it leaves too little of the hook deadline
    for the queue write, the review still queues and the hook falls back to
    its ordinary prompt. The key goes in the store request's top-level
    ``integrity_key_b64`` and ``integrity_key_id`` args, which the request
    digest never covers.
    """

    if not _notice_time_left(deadline):
        return None
    key = hook_authority_integrity_key(cast("GuardStore", store), create_key=True)
    if key is None or not _notice_time_left(deadline):
        return None
    return key


# Below this much of the hook deadline the notice is dropped, so the key read
# never costs the review its queue write.
_NOTICE_DEADLINE_MARGIN_SECONDS = 1.0


def _notice_time_left(deadline: float | None) -> bool:
    return deadline is None or deadline - time.monotonic() > _NOTICE_DEADLINE_MARGIN_SECONDS


__all__ = [
    "pause_native_pre_tool_for_approval",
    "queue_native_pre_tool_review",
]
