"""Route contained-test receipts on the direct CLI hook path.

The daemon rewrites an eligible native containment receipt into the
contained sink before answering. Hook clients fall back to ``guard hook``
when the daemon is down, so this path must apply the same rewrite or the
harness sees a bare denial for ordinary test commands.

Which step a result takes is the resident's ``containment_route`` answer, the
same one the daemon asks, so both paths route a call identically. No answer
raises ``NativeHookDecisionError`` and the caller answers with the host outage
response.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from ..action_lattice import normalize_guard_action
from ..adapters.zcode_contained_tests import route_zcode_containment
from ..daemon.hook_contained_grant import granted_containment_response
from ..daemon.hook_fail_closed import render_pre_tool
from ..native_hook_containment_route import edge_containment_route
from .commands_support_command_activity import record_pre_hook_command_activity_best_effort

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext
    from ..store import GuardStore


def emit_native_containment_route(
    edge: object,
    payload: dict[str, object],
    context: HarnessContext,
    workspace: Path | None,
    output_stream: TextIO | None,
    store: GuardStore,
) -> int | None:
    """Emit the contained-sink rewrite, or return ``None`` to keep the normal render."""

    if not isinstance(edge, Mapping):
        return None
    result = edge.get("result")
    if not isinstance(result, Mapping):
        return None
    route = edge_containment_route(
        edge,
        result,
        event_name=edge.get("event_name"),
        recording_only=bool(edge.get("recording_only")),
        guard_home=context.guard_home,
    )
    if route == "none":
        return None
    harness = str(edge.get("harness") or "")
    if route == "grant":
        # An outside-roots review this device's grant covers runs contained too.
        routed = granted_containment_response(
            store,
            result,
            harness=harness,
            payload=payload,
            guard_home=context.guard_home,
            home_dir=context.home_dir,
            workspace=workspace,
        )
        if routed is None:
            return None
    else:
        receipt = render_pre_tool(harness, result, guard_home=context.guard_home)
        routed = route_zcode_containment(
            receipt,
            harness=harness,
            payload=payload,
            guard_home=context.guard_home,
            home_dir=context.home_dir,
            workspace=workspace,
        )
        if routed is receipt:
            return None
    # The daemon records this PreToolUse activity too; keep history the same when it is down.
    native_receipt = edge.get("receipt")
    receipt_id = native_receipt.get("decision_id") if isinstance(native_receipt, Mapping) else None
    record_pre_hook_command_activity_best_effort(
        store=store,
        guard_home=context.guard_home,
        harness=harness,
        event="PreToolUse",
        payload=payload,
        policy_action=normalize_guard_action(routed.get("policy_action")),
        receipt_id=receipt_id if isinstance(receipt_id, str) else None,
        prompted=False,
        cwd=workspace,
        home_dir=context.home_dir,
    )
    stream = output_stream if output_stream is not None else sys.stdout
    stream.write(json.dumps(routed, ensure_ascii=False, separators=(",", ":")) + "\n")
    stream.flush()
    return 0


__all__ = ["emit_native_containment_route"]
