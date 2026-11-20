"""Deterministic responses when the resident cannot identify a hook event.

Structured-output helpers in this module are outage-only adapters. The normal
structured-output decision is made by the Rust edge from its authenticated
direct-lane binding.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..native_content_sensitivity import content_query
from ..native_policy_snapshot_direct_lane_structured import structured_output_view
from .hook_availability_policy import availability_harness_response, canonical_hook_event_name

if TYPE_CHECKING:
    from .hook_worker import HookWorker

_PERMISSION_PASSTHROUGH_HARNESSES = frozenset({"codex", "copilot", "devin", "zcode", "muse"})
_LOG = logging.getLogger(__name__)
MEDIATION_FIELD = "structured_content_mediation"
_MEDIATION_SCHEMA = "guard-structured-content-mediation.v1"
_PI_ALIASES = {"pi-agent": "pi", "pi-coding-agent": "pi", "oh-my-pi": "omp"}


def withholds_structured_destination(*, harness: str, event_name: str) -> bool:
    normalized = harness.strip().lower().replace("_", "-")
    return event_name == "PostToolUse" and _PI_ALIASES.get(normalized, normalized) in {"pi", "omp"}


def _withheld(reason_code: str, native_decision_id: object = None) -> dict[str, object]:
    disposition: dict[str, object] = {
        "schema": _MEDIATION_SCHEMA,
        "action": "withhold",
        "reason_code": reason_code,
    }
    if isinstance(native_decision_id, str) and native_decision_id:
        disposition["native_decision_id"] = native_decision_id
    return disposition


def withhold_structured_destination(response: dict[str, object]) -> dict[str, object]:
    """Withhold structured output when native proof is unavailable."""

    return {**response, MEDIATION_FIELD: _withheld("structured_native_edge_unavailable")}


def read_structured_view(load_config: Callable[[], object]) -> dict[str, object]:
    """Read the managed view used only by the outage-only overlay."""

    try:
        config = load_config()
        view = None if config is None else structured_output_view(config)
    except Exception as exc:
        _LOG.warning("structured managed policy read failed: %s", type(exc).__name__)
        view = None
    return view if view is not None else {}


def structured_destination_required(view: Mapping[str, object], *, harness: str) -> bool:
    """Return whether the managed policy requires withholding this destination."""

    if not view:
        return True
    try:
        result = content_query("resolution", {"config": dict(view), "harness": harness})
    except Exception:
        return True
    return not (isinstance(result, dict) and result.get("required") is False)


def unavailable_event_response(
    worker: HookWorker,
    *,
    payload: dict[str, object],
    harness: str,
    guard_home: Path,
    workspace: Path | None,
    deadline: float | None,
) -> dict[str, object]:
    """Return a fail-safe response after the resident misses event identity."""

    fallback_event = canonical_hook_event_name(payload, guard_home=guard_home, deadline=deadline)
    if fallback_event in {"PostToolUse", "PostToolUseFailure"}:
        from ..cli.commands_support_command_activity import hook_post_succeeded

        worker._record_post_tool_activity(
            harness=harness,
            payload=payload,
            succeeded=hook_post_succeeded(fallback_event, payload),
        )
    normalized_harness = harness.strip().lower().replace("_", "-")
    if fallback_event == "PermissionRequest":
        if normalized_harness == "claude-code":
            return {
                "guard_permission_passthrough": True,
                "hookSpecificOutput": {"hookEventName": "PermissionRequest"},
            }
        if normalized_harness in _PERMISSION_PASSTHROUGH_HARNESSES:
            return {"hookSpecificOutput": {"hookEventName": "PermissionRequest"}}
    response = availability_harness_response(
        harness=harness,
        event_name=fallback_event,
        reason_code={
            "PreToolUse": "native_pre_tool_unavailable",
            "PostToolUse": "native_post_tool_unavailable",
        }.get(fallback_event, "native_hook_event_unavailable"),
        reason="HOL Guard could not identify this hook event safely.",
    )
    return worker._apply_structured_unavailable_overlay(
        response,
        harness=harness,
        event_name=fallback_event,
        guard_home=guard_home,
        workspace=workspace,
    )
