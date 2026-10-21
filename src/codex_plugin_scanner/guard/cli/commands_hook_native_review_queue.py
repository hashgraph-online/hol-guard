"""Queue a reviewed artifact verdict for approval.

The resident's review route says an artifact verdict goes to the approval
center; this module does the daemon and store I/O that queueing takes and
binds the result into the response payload. Which verdicts queue is never
decided here.
"""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

from .commands_support import *

if TYPE_CHECKING:
    from ._commands_shared import _hook_command_text, _now
    from .commands_support_hook_payload import _action_envelope_json, _approval_surface_policy_for_flow
    from .commands_support_interaction import (
        _bind_hook_blocked_operation_queue,
        _codex_bridge_wait_process,
        _codex_browser_wait_metadata,
        _preferred_approval_review_url,
    )
    from .commands_support_permission_store import _attach_cursor_pending_approval_request_ids
    from .commands_support_runtime_artifacts import _optional_string
    from .commands_support_runtime_policy import _approval_delivery_payload, _localize_pending_approval_copy
    from .commands_support_runtime_resolution import (
        _canonical_harness_name,
        _runtime_detection,
        _runtime_request_summary,
    )


from ..daemon.client import GuardSurfaceDaemonClient, load_guard_surface_daemon_client
from ..retry_lineage import capture_retry_lineage
from ._commands_shared import *
from .commands_hook_native_state import NativeArtifactHookState
from .commands_parser_helpers import *


def _browser_wait_binding(
    *,
    args: argparse.Namespace,
    event_name: str,
    policy_action: str,
    config: GuardConfig,
    payload: Mapping[str, object],
    json_daemon_bridge: bool = False,
) -> tuple[dict[str, object], bool | None]:
    metadata = _codex_browser_wait_metadata(
        args=args,
        event_name=event_name,
        policy_action=policy_action,
        config=config,
        payload=payload,
        json_daemon_bridge=json_daemon_bridge,
    )
    if metadata.get("codex_hook_waits_for_browser_approval") is not True:
        return metadata, False
    if _codex_bridge_wait_process(payload) is not None:
        return metadata, True
    return metadata, None


def queue_native_approval(
    state: NativeArtifactHookState,
    args: argparse.Namespace,
    *,
    attach_cursor_request_ids: bool,
    config: GuardConfig,
    context: HarnessContext,
    guard_home: Path,
    managed_install: dict[str, object] | None,
    payload: Mapping[str, object],
    store: GuardStore,
    workspace: Path | None,
) -> tuple[GuardSurfaceDaemonClient | None, bool | None]:
    """Queue the verdict and return the browser approval's daemon binding.

    The pair is the daemon client the hook may wait on and whether a browser
    wait is bound to it. Both are ``None`` when the queue fell back to the
    local store.
    """

    payload_map = dict(payload)
    response_payload = state.response_payload
    event_name = state.event_name
    policy_action = state.policy_action
    runtime_artifact = state.runtime_artifact
    action_envelope = state.action_envelope
    approval_flow = get_adapter(args.harness).approval_flow(managed_install=managed_install)
    approval_center_url = schedule_guard_daemon_ensure(
        guard_home,
        home_dir=context.home_dir,
    )
    runtime_detection = _runtime_detection(args.harness, runtime_artifact)
    package_evaluation_to_dict = getattr(state.package_evaluation, "to_dict", None)
    evaluation_payload: dict[str, object] = {
        "artifacts": [
            {
                "artifact_id": state.artifact_id,
                "artifact_name": state.artifact_name,
                "artifact_hash": state.runtime_artifact_hash,
                "policy_action": policy_action,
                "changed_fields": state.changed_capabilities,
                "artifact_type": runtime_artifact.artifact_type,
                "source_scope": runtime_artifact.source_scope,
                "config_path": runtime_artifact.config_path,
                "launch_target": _runtime_request_summary(runtime_artifact),
                "risk_summary": state.risk_summary,
                "action_envelope_json": _action_envelope_json(action_envelope),
                "decision_v2_json": state.decision_v2_payload,
                "scanner_evidence": state.scanner_evidence_payload,
                "supply_chain_evaluation": (
                    package_evaluation_to_dict() if callable(package_evaluation_to_dict) else None
                ),
            }
        ]
    }
    browser_approval_daemon_client: GuardSurfaceDaemonClient | None = None
    try:
        daemon_client: GuardSurfaceDaemonClient | None = load_guard_surface_daemon_client(guard_home)
    except (RuntimeError, OSError):
        # A daemon start past its lifecycle deadline raises TimeoutError, an OSError.
        daemon_client = None
    browser_wait_metadata, browser_approval_wait_bound = _browser_wait_binding(
        args=args,
        event_name=event_name,
        policy_action=policy_action,
        config=config,
        payload=payload_map,
        json_daemon_bridge=daemon_client is not None,
    )
    hook_metadata: dict[str, object] = {
        "tool_name": str(payload.get("tool_name", "")),
        "event": str(payload.get("event", "")),
        "hook_event_name": event_name,
        **browser_wait_metadata,
        "command_text": _hook_command_text(payload_map),
        "workspace": str(workspace) if workspace else None,
        **(
            codex_resume_metadata_from_hook_payload(payload_map)
            if _canonical_harness_name(args.harness) == "codex"
            else {}
        ),
    }
    retry_lineage = capture_retry_lineage(
        payload_map,
        harness=str(args.harness),
        workspace=str(workspace) if workspace else None,
        action_envelope=action_envelope.to_dict() if action_envelope is not None else None,
    )
    if retry_lineage is not None:
        hook_metadata["retry_lineage"] = retry_lineage
    try:
        if daemon_client is None:
            raise RuntimeError("guard surface daemon client unavailable")
        session = daemon_client.start_session(
            harness=args.harness,
            surface="harness-adapter",
            workspace=str(workspace) if workspace else None,
            client_name=f"{args.harness}-hook",
            client_title=f"{args.harness} hook",
            client_version="1.0.0",
            capabilities=["approval-resolution", "receipt-view"],
        )
        response_payload["session_id"] = str(session["session_id"])
        blocked_operation = daemon_client.queue_blocked_operation(
            session_id=str(session["session_id"]),
            operation_type="tool_call",
            harness=args.harness,
            metadata=hook_metadata,
            detection=runtime_detection.to_dict(),
            evaluation=evaluation_payload,
            approval_center_url=approval_center_url,
            approval_surface_policy=_approval_surface_policy_for_flow(
                config.approval_surface_policy,
                approval_flow,
            ),
            open_key=state.artifact_id,
            redaction_level=config.receipt_redaction_level,
        )
        browser_approval_daemon_client = daemon_client
    except RuntimeError:
        try:
            queued = queue_blocked_approvals(
                redaction_level=config.receipt_redaction_level,
                detection=runtime_detection,
                evaluation=evaluation_payload,
                store=store,
                approval_center_url=approval_center_url,
                now=_now(),
                continuation_operation={
                    "created_at": _now(),
                    "harness": args.harness,
                    "metadata": hook_metadata,
                    "status": "waiting_on_approval",
                    "updated_at": _now(),
                },
            )
        except (RuntimeError, OSError) as queue_error:
            # A local queue past a native or store deadline (TimeoutError) keeps the native deny.
            queued = approvals_queued_before(queue_error)
        _bind_hook_blocked_operation_queue(
            harness=args.harness,
            approval_center_url=approval_center_url,
            response_payload=response_payload,
            queued=queued,
        )
    else:
        queued = _bind_hook_blocked_operation_queue(
            harness=args.harness,
            approval_center_url=approval_center_url,
            response_payload=response_payload,
            queued=[],
            blocked_operation=blocked_operation,
        )
    if attach_cursor_request_ids:
        _attach_cursor_pending_approval_request_ids(
            store=store,
            payload=payload_map,
            response_payload=response_payload,
        )
    response_payload["approval_center_url"] = approval_center_url
    response_payload["review_hint"] = approval_center_hint(
        context=context,
        harness=args.harness,
        approval_center_url=approval_center_url,
        queued=queued,
        managed_install=managed_install,
        request_id=_optional_string(response_payload.get("primary_approval_request_id")),
        artifact_id=_optional_string(response_payload.get("artifact_id")),
        review_url=_preferred_approval_review_url(response_payload, harness=args.harness),
    )
    response_payload["approval_delivery"] = _approval_delivery_payload(
        args.harness,
        managed_install=managed_install,
    )
    _localize_pending_approval_copy(response_payload, harness=args.harness)
    return browser_approval_daemon_client, browser_approval_wait_bound


__all__ = [
    "queue_native_approval",
]
