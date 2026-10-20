"""Route an outside-roots review the local CLI grant covers into the workspace sandbox.

Rust reviews a command the workspace sandbox cannot run because its program
lives outside the sandbox's executable roots. When this device allowed that
CLI, the grant does not lift the review to ``allow``: the command runs in the
sandbox widened by the grant (``workspace-contained-grant-v1``). The sink asks
the store for the grant again itself, so nothing here is trusted beyond the
routing. A blocked or undecided CLI, or a call the sink cannot take, keeps the
review.

The sandbox requirement itself is the resident's: it answers the grant step
with the review fields the command is routed to, and this module copies them.
A resident that cannot be reached sends no route, so the review stands.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from .hook_fail_closed import render_pre_tool
from .hook_native_exact_action import launch_cwd, launch_path
from .hook_native_saved_approval import _native_review_is_overridable
from .hook_request_parsing import pre_tool_command

if TYPE_CHECKING:
    from ..store import GuardStore

_LOGGER = logging.getLogger(__name__)
OUTSIDE_ROOTS_REASON = "native_workspace_containment_executable_outside_roots"
_RECEIPT_ONLY_FIELD = "guard_containment_receipt_only"


def granted_containment_result(
    store: GuardStore,
    result: Mapping[str, object],
    *,
    payload: Mapping[str, object],
    workspace: Path | None,
    home_dir: Path | None,
) -> dict[str, object] | None:
    """The sandbox requirement an allowed grant turns an outside-roots review into.

    Only a review the saved-approval path could also override qualifies: a Guard
    control or package action never routes into the sandbox, whatever the grant.
    """
    if (
        result.get("minimum_action") != "review"
        or result.get("policy_action") != "review"
        or result.get("reason_code") != OUTSIDE_ROOTS_REASON
        or not _native_review_is_overridable(result)
    ):
        return None
    command = pre_tool_command(payload)
    cwd = launch_cwd(payload, workspace)
    if command is None or cwd is None:
        return None
    from ..local_cli_hook import ALLOW_CONTAINED_WITH_GRANT, local_cli_contained_grant

    try:
        decision = local_cli_contained_grant(
            store,
            command=command,
            cwd=cwd,
            home_dir=home_dir,
            current_action="review",
            reason_code=OUTSIDE_ROOTS_REASON,
            path=launch_path(payload),
        )
    except Exception:
        _LOGGER.warning("local CLI grant lookup failed", exc_info=True)
        return None
    if decision is None or decision[0] != ALLOW_CONTAINED_WITH_GRANT or decision[1] is None:
        return None
    route = decision[2]
    if route is None:
        return None
    return {**result, **route}


def granted_containment_response(
    store: GuardStore,
    result: Mapping[str, object],
    *,
    harness: str,
    payload: Mapping[str, object],
    guard_home: Path,
    home_dir: Path,
    workspace: Path | None,
    deadline: float | None = None,
) -> dict[str, object] | None:
    """The contained-sink rewrite for a granted outside-roots review, or ``None`` to keep it.

    A receipt-only call is the sink re-authorizing, so it gets the sandbox
    receipt itself; any other call is answered only when the sink takes it.
    """
    granted = granted_containment_result(store, result, payload=payload, workspace=workspace, home_dir=home_dir)
    if granted is None:
        return None
    from ..adapters.zcode_contained_tests import route_zcode_containment

    receipt = render_pre_tool(harness, granted, guard_home=guard_home, deadline=deadline)
    if payload.get(_RECEIPT_ONLY_FIELD) is True:
        return receipt
    routed = route_zcode_containment(
        receipt, harness=harness, payload=payload, guard_home=guard_home, home_dir=home_dir, workspace=workspace
    )
    return None if routed is receipt else routed


__all__ = ["granted_containment_response", "granted_containment_result"]
