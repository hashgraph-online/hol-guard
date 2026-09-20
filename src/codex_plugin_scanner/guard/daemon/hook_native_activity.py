"""Native activity helpers preserving the hook worker lookup surface."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .hook_worker_native import _HookWorkerNativeHost


def _record_native_pre_activity(
    host: _HookWorkerNativeHost,
    harness: str,
    payload: Mapping[str, object],
    response: dict[str, object],
    receipt: Mapping[str, object] | None = None,
) -> dict[str, object]:
    submit = getattr(host.activity_writer, "submit_command_activity", None)
    if callable(submit):
        from .hook_worker_native import suppress

        with suppress(Exception):
            submit(
                harness=harness,
                event="PreToolUse",
                payload=payload,
                succeeded=True,
                policy_action=response.get("policy_action"),
                receipt_id=receipt.get("decision_id") if receipt is not None else None,
                prompted=response.get("prompted") is True,
                approval_reuse_status=response.get("approval_reuse_status", "not-applicable"),
            )
    return response


def _record_unavailable_native(
    host: _HookWorkerNativeHost,
    payload: dict[str, object],
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    workspace: Path | None,
    home_dir: Path,
    guard_home: Path,
    recording_only: bool,
) -> dict[str, object]:
    from . import hook_worker_native as api

    response = api.availability_harness_response(
        payload,
        harness=harness,
        event_name=event_name,
        reason_code=reason_code,
        reason="HOL Guard could not complete the native hook decision safely.",
        workspace=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
        recording_only=recording_only,
    )
    route = "native_degraded" if response.get("reason_code") == "native_degraded_emergency_safe" else "native_fail_safe"
    host.metrics.record_route(route)
    if event_name == "PreToolUse":
        writer = host.activity_writer
        submit = getattr(writer, "submit_command_activity", None)
        if callable(submit):
            from .hook_worker_native import suppress

            with suppress(Exception):
                _ = submit(
                    harness=harness,
                    event=event_name,
                    payload=payload,
                    succeeded=str(response.get("policy_action") or "") != "block",
                    policy_action=response.get("policy_action"),
                )
    return response
