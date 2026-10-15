"""Present native availability failures to the managed harness."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..adapters.base import HarnessContext
from ..daemon.hook_availability_policy import availability_harness_response
from .commands_support_interaction import _emit

if TYPE_CHECKING:
    from ..daemon.hook_worker import HookWorker


def _availability_response_is_deny(response: Mapping[str, object]) -> bool:
    """Return True when an availability response denies the action.

    The deny signal is encoded differently per harness envelope: Cursor uses a
    top-level ``permission`` field, Codex/Kimi/Claude wire envelopes carry
    ``hookSpecificOutput.permissionDecision``, and the generic/superagent and
    managed envelopes carry a top-level ``policy_action``. None of these can be
    treated as allow when absent — but the rc for a missing signal must not
    silently block either, so callers only consult this after checking the
    specific envelope shape they emitted.
    """

    if not isinstance(response, Mapping):
        return False
    permission = response.get("permission")
    if isinstance(permission, str):
        return permission.strip().lower() == "deny"
    hook_output = response.get("hookSpecificOutput")
    if isinstance(hook_output, Mapping):
        decision = hook_output.get("permissionDecision")
        if isinstance(decision, str):
            return decision.strip().lower() == "deny"
        decision = hook_output.get("decision")
        if isinstance(decision, str):
            return decision.strip().lower() in {"deny", "block", "review"}
    policy_action = response.get("policy_action")
    if isinstance(policy_action, str):
        return policy_action.strip().lower() in {
            "deny",
            "block",
            "review",
            "require-reapproval",
            "sandbox-required",
        }
    # No deny signal present -> not a deny (fail-open on the verdict axis only
    # when the envelope itself carries no decision; callers gate on shape).
    return False


def _native_unavailable_exit_code(
    args: argparse.Namespace,
    response: Mapping[str, object],
    event_name: str,
) -> int:
    """Map an emitted availability response to the harness's exit contract.

    Exit codes are per-harness and per-action, not a global constant:
    Cursor's ``cursor_fallback_permission`` returns ``2`` for protected events,
    grok's ``grok_hook_process_exit`` returns ``2`` for blocking actions but
    ``0`` in recording-only mode, zcode's ``zcode_hook_process_exit`` returns
    ``2`` for block but ``0`` for PreToolUse ``ask`` so the permission prompt
    opens, and the generic CLI contract in ``commands_hook_native_finish``
    returns ``1`` for ``review``/``require-reapproval``/``sandbox-required``/
    ``block`` and ``0`` otherwise. Feeding the emitted payload back through
    the harness's own mapper keeps a denied deny a deny (PRD S10: unavailable
    authority cannot produce permit) without inventing a blanket rc that
    breaks harnesses reading only the JSON envelope.
    """

    from .commands_hook_native_finish import _canonical_harness_name
    from .native_hook_exit_code import native_hook_verdict_exit_code

    harness = _canonical_harness_name(getattr(args, "harness", "codex"))
    deny = _availability_response_is_deny(response)
    # Deny responses resolve to the fail-closed "block" action; allow / observe
    # responses resolve to "allow".  The shared per-harness contract decides rc
    # so this path can never diverge from the finish path's verdict mapping.
    return native_hook_verdict_exit_code(harness, "block" if deny else "allow", event_name=event_name)


def _emit_native_unavailable(
    args: argparse.Namespace,
    *,
    payload: Mapping[str, object],
    workspace: Path | None,
    context: HarnessContext,
    event_name: str,
    reason_code: str,
    worker: HookWorker,
    recording_only: bool = False,
) -> int:
    response = availability_harness_response(
        dict(payload),
        harness=args.harness,
        event_name=event_name,
        reason_code=reason_code,
        reason="HOL Guard could not complete the native hook decision safely.",
        workspace=workspace,
        home_dir=context.home_dir,
        guard_home=context.guard_home,
        recording_only=recording_only,
    )
    # The native edge has already returned before this projection.  Keep the
    # native availability response and overlay only the managed model-visible
    # structured destination; this must not invent a native result, receipt,
    # or decision identifier.
    response = worker._apply_structured_unavailable_overlay(
        response,
        harness=args.harness,
        event_name=event_name,
        guard_home=context.guard_home,
        workspace=workspace,
    )
    _emit("hook", response, True)
    # rc mirrors the emitted verdict through the harness's own adapter contract:
    # unavailable authority cannot permit a protected action, but recording-only
    # allow responses keep rc=0 so an outage does not fabricate a block.
    return _native_unavailable_exit_code(args, response, event_name)
