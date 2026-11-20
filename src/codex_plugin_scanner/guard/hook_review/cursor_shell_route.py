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

The resident decides all of it through its ``cursor_shell_route`` render:
which route a call takes (``route``), whether a probe is reviewed at all
(``probe_gate``), what a reviewed probe is answered (``probe_response``) and
whether a sink command is admitted. This module
gathers the facts (the workspace, the policy snapshot, the daemon's edge
review), asks, and returns the answer. A probe that fails anywhere here is
the plain allow, and a sink call that fails is reviewed as usual.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .hook_worker import HookWorker

_LOGGER = logging.getLogger(__name__)

_CURSOR = "cursor"
_PRE_TOOL_USE = "PreToolUse"
# What a probe is answered when the review that would route it fails.
# beforeShellExecution still reviews the call that runs.
_PLAIN_ALLOW: dict[str, object] = {"policy_action": "allow"}


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

    try:
        route = _ask("route", {"payload": dict(payload)}, guard_home=guard_home, deadline=deadline)
    except Exception:
        _LOGGER.warning("Cursor shell route decision failed", exc_info=True)
        return None
    if route == "probe":
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
        return routed if routed is not None else dict(_PLAIN_ALLOW)
    if route == "sink" and workspace is not None:
        try:
            return _resident_route(
                payload, home_dir=home_dir, guard_home=guard_home, workspace=workspace, deadline=deadline
            )
        except Exception:
            # The call is reviewed as usual, so a sink it does not admit runs nowhere.
            _LOGGER.warning("Cursor shell sink admission failed", exc_info=True)
    return None


def _ask(op: str, params: dict[str, object], *, guard_home: Path, deadline: float | None) -> object | None:
    from ..native_hook_render import native_render_cli

    rendered = native_render_cli(
        "cursor_shell_route", _CURSOR, {"op": op, **params}, guard_home=guard_home, deadline=deadline
    )
    document = rendered[1] if rendered is not None else None
    return document.get("value") if document is not None else None


def _probe_response(
    worker: HookWorker,
    *,
    payload: Mapping[str, object],
    home_dir: Path,
    guard_home: Path,
    workspace: Path | None,
    deadline: float | None,
) -> dict[str, object] | None:
    snapshot = worker._native_policy_snapshot(workspace, deadline=deadline) if workspace is not None else None
    reviewed = _ask(
        "probe_gate",
        {"snapshot": snapshot, "has_workspace": workspace is not None},
        guard_home=guard_home,
        deadline=deadline,
    )
    if reviewed is not True or workspace is None:
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
    answer = _ask("probe_response", {"edge": edge}, guard_home=guard_home, deadline=deadline)
    return dict(answer) if isinstance(answer, dict) else None


def _resident_route(
    payload: Mapping[str, object],
    *,
    home_dir: Path,
    guard_home: Path,
    workspace: Path,
    deadline: float | None = None,
) -> dict[str, object] | None:
    from ..contained_sink_command import contained_sink_command_prefix
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


__all__ = ["cursor_shell_route_response"]
