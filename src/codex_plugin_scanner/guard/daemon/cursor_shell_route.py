"""Cursor's contained route: the silent ``preToolUse`` probe and its sink.

Cursor sends a shell call to two hooks. Its ``preToolUse`` hook for ``Shell``
may rewrite the call through ``updated_input``; ``beforeShellExecution``,
which runs next with the rewritten command, cannot rewrite anything. Guard
therefore treats ``preToolUse`` as a probe: it asks the native authority
whether the call would run in the contained sink and, when it would, answers
with the sink command. Every other probe answer is a plain allow, and the
probe records nothing, so ``beforeShellExecution`` stays the one check the
user sees.

``beforeShellExecution`` then admits the sink command the probe wrote: the
exact argv this daemon quotes, for this daemon's Guard home, a workspace that
matches the hook's, and a private snapshot the sink will read. The sink
re-authorizes the saved call before it runs anything, so admitting the
command never widens what runs.

The resident reads both: this module reviews a probe through the daemon's
edge with the sink command it binds, and the edge answers a probe it routes
to the sink as the direct lane does. A probe the edge does not answer is the
plain allow. A sink call goes to the resident's ``cursor_shell_route``
render with the call and the sink command.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .hook_worker import HookWorker

_LOGGER = logging.getLogger(__name__)

_CURSOR = "cursor"
_PRE_TOOL_USE = "PreToolUse"
_SHELL_TOOL = "Shell"
_SOURCE_HOOK_FIELD = "cursor_source_hook_event"
_PROBE_FIELD = "cursor_route_probe"
_BEFORE_SHELL = "beforeShellExecution"
_RECEIPT_ONLY_FIELD = "guard_containment_receipt_only"
_SINK_VERB = "execute-contained-test"
# The runtime's own workspace sandbox sink, which a probe may name instead.
_NATIVE_SINK_VERB = "contained-workspace-sink"
_ALLOW: dict[str, object] = {"policy_action": "allow"}
_SINK_ROUTE = "sink"
_ROUTED = "native_contained_execution_routed"


def cursor_shell_route_response(
    worker: HookWorker,
    *,
    payload: Mapping[str, object],
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    deadline: float | None,
) -> dict[str, object] | None:
    """The daemon's answer to a Cursor probe or sink call, or ``None`` to review it as usual."""

    if sys.platform == "win32" or payload.get(_RECEIPT_ONLY_FIELD) is not None:
        return None
    if is_cursor_shell_probe(payload):
        try:
            routed = _probe_response(
                worker,
                payload=payload,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
                deadline=deadline,
            )
        except Exception:
            _LOGGER.warning("Cursor shell route probe failed", exc_info=True)
            routed = None
        # beforeShellExecution still reviews the call that runs.
        return routed if routed is not None else dict(_ALLOW)
    if workspace is not None and payload.get(_SOURCE_HOOK_FIELD) == _BEFORE_SHELL and _names_sink(payload):
        try:
            return _resident_route(
                payload, home_dir=home_dir, guard_home=guard_home, workspace=workspace, deadline=deadline
            )
        except Exception:
            # The call is reviewed as usual, so a sink it does not admit runs nowhere.
            _LOGGER.warning("Cursor shell sink admission failed", exc_info=True)
    return None


def is_cursor_shell_probe(payload: Mapping[str, object]) -> bool:
    """Cursor's own ``preToolUse`` for ``Shell``, which names no source hook.

    Guard's Cursor hook names its probe with ``cursor_route_probe``. Any other
    caller that sends a ``Shell`` call for Cursor gets the ordinary review.
    """

    return (
        payload.get("hook_event_name") == _PRE_TOOL_USE
        and payload.get("tool_name") == _SHELL_TOOL
        and _SOURCE_HOOK_FIELD not in payload
        and payload.get(_PROBE_FIELD) is True
    )


def _names_sink(payload: Mapping[str, object]) -> bool:
    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    return isinstance(command, str) and (_SINK_VERB in command or _NATIVE_SINK_VERB in command)


def _probe_response(
    worker: HookWorker,
    *,
    payload: Mapping[str, object],
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    deadline: float | None,
) -> dict[str, object] | None:
    from ..native_policy_snapshot_harness_postures import recording_only_for_binding

    if workspace is None:
        return None
    snapshot = worker._native_policy_snapshot(workspace, deadline=deadline)
    if snapshot is None or recording_only_for_binding(snapshot, _CURSOR):
        return None
    edge = worker._review_raw_hook_native(
        payload=dict(payload),
        harness=_CURSOR,
        event=_PRE_TOOL_USE,
        guard_home=guard_home,
        home_dir=home_dir,
        cwd=workspace,
        source_ref_external_allowed=False,
        observe_mode=False,
        deadline=deadline,
        policy_snapshot=snapshot,
        containment_sink=True,
    )
    if edge is None:
        return None
    # The edge rewrites only a probe it routes to the sink; any other is the
    # plain allow.
    if edge.get("containment_route") != _SINK_ROUTE:
        return dict(_ALLOW)
    # An edge whose probe answer failed falls back to the generic rewrite,
    # which keeps the receipt, so only probe answers count.
    response = edge.get("harness_response")
    mark = edge.get("containment_rewrite")
    if (
        isinstance(response, dict)
        and ((mark == "kept" and response == _ALLOW) or (mark == "routed" and response.get("reason_code") == _ROUTED))
        and response.get("policy_action") == "allow"
    ):
        return dict(response)
    return None


def _resident_route(
    payload: Mapping[str, object],
    *,
    home_dir: Path,
    guard_home: Path,
    workspace: Path,
    deadline: float | None = None,
) -> dict[str, object] | None:
    from ..adapters.zcode_contained_tests import contained_sink_command_prefix
    from ..native_hook_render import native_render_cli

    params: dict[str, object] = {
        "payload": dict(payload),
        "workspace": str(workspace),
        "home_dir": str(home_dir),
        "guard_home": str(guard_home),
        "sink_command": list(contained_sink_command_prefix()),
        # This daemon admits the runtime's own sink command too.
        "native_sink": True,
    }
    rendered = native_render_cli("cursor_shell_route", _CURSOR, params, guard_home=guard_home, deadline=deadline)
    value = rendered[1].get("value") if rendered is not None and rendered[1] is not None else None
    return dict(value) if isinstance(value, dict) else None


__all__ = ["cursor_shell_route_response", "is_cursor_shell_probe"]
