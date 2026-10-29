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
to the sink as the direct lane does. A resident that predates that answer
gets the edge, the call and the sink command through its
``cursor_shell_route`` render instead, as does a sink call.
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
_ALLOW: dict[str, object] = {"policy_action": "allow"}
_SINK_ROUTE = "sink"
# A resident that advertises this answers the probe in its edge when the
# daemon sends the sink argv; an older one leaves it to the render.
_EDGE_PROBE_FEATURE = "edge-cursor-probe-v1"
_ROUTED = "native_contained_execution_routed"
# The edge fields the resident reads to route a probe.
_EDGE_FIELDS = ("harness", "event_name", "containment_route", "result")


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
                payload, None, home_dir=home_dir, guard_home=guard_home, workspace=workspace, deadline=deadline
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
    return isinstance(command, str) and _SINK_VERB in command


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
    capabilities = worker._native_runtime_status().capabilities
    edge_answers = capabilities is not None and _EDGE_PROBE_FEATURE in capabilities.features
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
        containment_sink=edge_answers,
    )
    if edge is None:
        return None
    # The resident rewrites only a probe the edge routes to the sink and
    # answers any other with the plain allow, so that one skips the call.
    if edge.get("containment_route") != _SINK_ROUTE:
        return dict(_ALLOW)
    # A resident replaced after the feature was read may answer with the
    # generic rewrite, which keeps the receipt, so only probe answers count.
    response = edge.get("harness_response")
    mark = edge.get("containment_rewrite")
    if (
        edge_answers
        and isinstance(response, dict)
        and ((mark == "kept" and response == _ALLOW) or (mark == "routed" and response.get("reason_code") == _ROUTED))
        and response.get("policy_action") == "allow"
    ):
        return dict(response)
    return _resident_route(
        payload, edge, home_dir=home_dir, guard_home=guard_home, workspace=workspace, deadline=deadline
    )


def _resident_route(
    payload: Mapping[str, object],
    edge: Mapping[str, object] | None,
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
    }
    if edge is not None:
        params["edge"] = {key: edge[key] for key in _EDGE_FIELDS if key in edge}
    rendered = native_render_cli("cursor_shell_route", _CURSOR, params, guard_home=guard_home, deadline=deadline)
    value = rendered[1].get("value") if rendered is not None and rendered[1] is not None else None
    return dict(value) if isinstance(value, dict) else None


__all__ = ["cursor_shell_route_response", "is_cursor_shell_probe"]
