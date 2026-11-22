"""Evidence handoff for the daemon's native hook responses."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from ..native_resident_client import native_resident_client_failure_code
from ..native_resident_revival import native_unavailable_reason
from ..resident_evidence_dispatch import run_resident_evidence
from .hook_availability_policy import availability_harness_response
from .hook_fail_closed import render_recording_only_pre_tool

if TYPE_CHECKING:
    from .hook_worker_native import _HookWorkerNativeHost


def _record_native_pre_activity(
    host: _HookWorkerNativeHost,
    harness: str,
    payload: Mapping[str, object],
    response: dict[str, object],
    receipt: Mapping[str, object] | None = None,
    *,
    recorded: bool = False,
) -> dict[str, object]:
    from ..runtime_transition_hook_probe import OBSERVATION_FIELD, transition_hook_observation

    # Bind diagnostics to this call's accepted receipt, never the worker's
    # shared last-receipt slot (other HTTP requests may run concurrently).
    observation = transition_hook_observation(payload, receipt)
    if observation is not None:
        response = {**response, OBSERVATION_FIELD: observation}
    submit = getattr(host.activity_writer, "submit_pre_tool_activity", None)
    # An edge that queued this activity behind its receipt says so.
    if callable(submit) and not recorded:
        receipt_id = receipt.get("decision_id") if receipt is not None else None
        # The hook has its verdict; the activity row records it. The writer
        # lives in the resident, so submitting here would spend a round trip
        # in front of the response rather than behind it.
        run_resident_evidence(
            host,
            lambda: submit(
                harness=harness,
                payload=payload,
                response=response,
                settled=True,
                receipt_id=receipt_id,
            ),
        )
    return response


def _record_unavailable_native(
    host: _HookWorkerNativeHost,
    payload: dict[str, object],
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    guard_home: Path,
    watch_continue: bool = False,
    deadline: float | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    failure_code = native_resident_client_failure_code()
    response = availability_harness_response(
        harness=harness,
        event_name=event_name,
        reason_code=reason_code,
        reason=reason
        or native_unavailable_reason(
            failure_code,
            "HOL Guard could not complete the native hook decision safely.",
        ),
        prompt_reason=reason or native_unavailable_reason(failure_code, "") or None,
        guard_home=guard_home,
        deadline=deadline,
    )
    if watch_continue and event_name == "PreToolUse":
        # Only a superseded Watch snapshot (resident reachable) keeps recording,
        # through the resident-rendered continue; any render failure keeps the
        # fixed deny above. Real outages never take this path.
        response = render_recording_only_pre_tool(
            harness,
            reason_code=reason_code,
            reason="Watch recorded this action without stopping it.",
            guard_home=guard_home,
            deadline=deadline,
            fallback=response,
        )
    host.metrics.record_route("native_fail_safe")
    if event_name == "PreToolUse":
        submit = getattr(host.activity_writer, "submit_pre_tool_activity", None)
        if callable(submit):
            run_resident_evidence(
                host,
                lambda: submit(
                    harness=harness,
                    payload=payload,
                    response=response,
                    settled=False,
                ),
            )
    return response
