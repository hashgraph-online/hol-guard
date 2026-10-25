"""Run a native hook through the handlers the resident route names.

The resident answers which handlers may answer a prepared hook, and in what
order (``hook_route``). This module holds what those handlers share, gathers
the facts the route reads, and runs the plan: each handler either answers with
an exit code or declines with ``None``, and the next one runs. It chooses
nothing itself, so when the resident cannot supply a route the caller answers
with the host outage response instead.
"""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from ..adapters.base import HarnessContext
from ..daemon.hook_request_parsing import runtime_hook_event_name
from ..models import GuardArtifact
from ..runtime.actions import GuardActionEnvelope
from ..store import GuardStore
from .commands_hook_native_availability import _emit_native_unavailable
from .commands_support_runtime_artifacts import _hook_event_name, _optional_string
from .commands_support_runtime_resolution import _canonical_harness_name, _is_copilot_permission_request

if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..daemon.hook_worker import HookWorker

ROUTE_UNANSWERED = "native_hook_route_unanswered"


@dataclass(slots=True)
class NativeHookRun:
    """One prepared hook: what every handler reads, and what handlers hand on."""

    args: argparse.Namespace
    config: GuardConfig
    context: HarnessContext
    payload: dict[str, object]
    runtime_workspace: Path | None
    store: GuardStore
    worker: HookWorker
    output_stream: TextIO | None
    managed_install: dict[str, object] | None
    workspace_was_explicit: bool
    action_envelope: GuardActionEnvelope | None
    copilot_runtime_tool_call: tuple[GuardArtifact, str, object] | None
    edge_timing: Mapping[str, float]
    claim_saved_approval: bool
    claimed_saved_allow_hash: str | None
    claimed_trusted_request_override: bool
    claimed_approval_request_id: str | None
    event_name: str = ""
    # Handed on by the native edge and runtime artifact handlers.
    edge: object = None
    runtime_artifact: GuardArtifact | None = None
    data_flow_signals: tuple[object, ...] = ()

    def edge_field(self, key: str) -> object:
        return self.edge.get(key) if isinstance(self.edge, Mapping) else None

    def edge_mapping(self, key: str) -> Mapping[str, object] | None:
        value = self.edge_field(key)
        return value if isinstance(value, Mapping) else None

    @property
    def recording_only(self) -> bool:
        return bool(self.edge_field("recording_only"))

    def unavailable(self, reason_code: str) -> int:
        """The host outage response, keeping the resident's reason code."""
        return _emit_native_unavailable(
            self.args,
            workspace=self.runtime_workspace,
            context=self.context,
            event_name=self.event_name,
            reason_code=reason_code,
            worker=self.worker,
        )


NativeHandler = Callable[[NativeHookRun], int | None]


def hook_route_inputs(
    args: argparse.Namespace,
    payload: Mapping[str, object],
    *,
    invoked_event: str,
    copilot_stage: str | None,
    copilot_tool_call_present: bool,
) -> dict[str, object]:
    """The facts the resident route reads; it decides nothing from anything else."""
    return {
        "harness": args.harness,
        "canonical_harness": _canonical_harness_name(args.harness),
        "invoked_event": invoked_event,
        "hook_event": _hook_event_name(dict(payload)) or "",
        "runtime_event": runtime_hook_event_name(payload),
        "notification_type": _optional_string(payload.get("notification_type")) or "",
        "copilot_stage": copilot_stage or "",
        "copilot_tool_call_present": copilot_tool_call_present,
        "copilot_permission_request": _is_copilot_permission_request(dict(payload)),
    }


def route_budget_seconds(edge_timing: Mapping[str, float], *, started_at: float | None = None) -> float | None:
    """What the harness still allows this hook, from the timing anchored at CLI entry.

    A hinted deadline is absolute. An explicit budget is a duration sampled at
    ``started_at``, so the time spent preparing the hook since then is spent.
    """
    deadline = edge_timing.get("deadline")
    if deadline is not None:
        return deadline - time.monotonic()
    budget = edge_timing.get("edge_budget_seconds")
    if budget is None or started_at is None:
        return budget
    return budget - max(0.0, time.monotonic() - started_at)


def run_route_plan(run: NativeHookRun, plan: Sequence[str], handlers: Mapping[str, NativeHandler]) -> int:
    """Run the planned handlers in order until one answers."""
    for name in plan:
        result = handlers[name](run)
        if result is not None:
            return result
    # Every plan ends in a handler that always answers; reaching here means the
    # route and the table disagree, which is an outage, never a verdict.
    return run.unavailable(ROUTE_UNANSWERED)


__all__ = [
    "ROUTE_UNANSWERED",
    "NativeHandler",
    "NativeHookRun",
    "hook_route_inputs",
    "route_budget_seconds",
    "run_route_plan",
]
