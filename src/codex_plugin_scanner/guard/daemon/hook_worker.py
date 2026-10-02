"""Daemon-resident hook worker for fast hook review.

This worker avoids Python startup/import cost and avoids calling the
CLI path for normal daemon hooks. It builds a ``HookReviewRequest``
from the HTTP payload and calls the configured local decision backend.

Security:
- Never lets unreviewed tool output reach the model.
- Never falls back to legacy CLI after a worker exception for a
  request that supplied only ``guard_source_ref`` without full output.
- Never calls ``run_guard_command()``.
- Native PostToolUse is decided by Rust for ``auto``/``force``. When review
  cannot complete, PostToolUse continues; protected PreToolUse pauses unless
  acknowledged recording-only mode applies. Explicit ``off`` is a fail-safe
  disablement with no Python semantic fallback.
- Supported generic PreToolUse is decided by Rust. Native failure denies
  protected actions without acknowledged recording-only mode authority.
  Explicit off/shadow have no production semantic fallback. Native block
  results stay mechanical. A command-policy authority block includes a local
  repair link and does not rebuild protection from the hook. The current
  action stays denied, and this worker never calls the CLI.
  Native review pauses the tool and queues an approval-center request; it
  never escapes to the Python semantic CLI path.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, final

from ..cli.commands_support_command_activity import (
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
)
from ..codex_binding_capture_writer import CodexBindingCaptureWriter
from ..config import load_guard_config
from ..native_hook_edge import review_raw_hook_native
from ..native_policy_snapshot import get_native_policy_snapshot_publisher
from ..native_policy_snapshot_acked import acked_snapshot_binding_for_store
from ..native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS
from ..native_runtime import NativeRuntimeStatus, native_mode, native_runtime_status, review_post_tool_native
from ..runtime.hook_review_types import (
    HookReviewRequest,
)
from .hook_availability_policy import availability_harness_response
from .hook_request_parsing import (
    build_hook_review_request,
    runtime_hook_event_name,
)
from .hook_worker_native import HookWorkerNativeMixin
from .hook_worker_responses import (
    harness_json_from_review_response,
)

if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..store import GuardStore


class CommandActivityWriter(Protocol):
    def submit_command_activity(
        self,
        *,
        harness: str,
        event: str,
        payload: Mapping[str, object],
        succeeded: bool,
    ) -> bool: ...


# Startup priming keeps the publish bound so a slow first publication never
# delays worker construction. Requests that arrive during a resident restart
# wait on the readiness bound instead, which needs a wider window everywhere:
# republication is slower on macOS and Windows, and Linux CI runners under
# parallel shard load miss the publish bound too.
_NATIVE_POLICY_STARTUP_READY_TIMEOUT_SECONDS = _PUBLISH_TIMEOUT_SECONDS
_NATIVE_POLICY_READY_TIMEOUT_SECONDS = 25.0
_TRANSIENT_RESIDENT_PUBLICATION_ERRORS = frozenset(
    {"native_policy_snapshot_resident_changed", "native_resident_restart_budget_busy"}
)


def _post_tool_unavailable_response(
    payload: dict[str, object],
    *,
    harness: str,
    reason_code: str,
    workspace: Path | None,
    home_dir: Path,
    guard_home: Path,
) -> dict[str, object]:
    return availability_harness_response(
        payload,
        harness=harness,
        event_name="PostToolUse",
        reason_code=reason_code,
        reason="HOL Guard could not complete the native local hook review safely.",
        workspace=workspace,
        home_dir=home_dir,
        guard_home=guard_home,
    )


@final
class HookWorker(HookWorkerNativeMixin):
    """Resident hook review worker for the daemon."""

    def __init__(
        self,
        *,
        store: GuardStore,
        activity_writer: CommandActivityWriter | None = None,
        capture_writer: CodexBindingCaptureWriter | None = None,
        wait_for_native_policy: bool = True,
        publish_native_policy: bool = True,
    ):
        self.store = store
        self.guard_home = store.guard_home
        self.activity_writer = activity_writer
        self.capture_writer = capture_writer
        self._publish_native_policy = publish_native_policy
        self._last_native_decision_receipt: dict[str, object] | None = None
        from .hook_metrics import HookMetricsRecorder

        self.metrics = HookMetricsRecorder()
        self.policy_snapshot_publisher = get_native_policy_snapshot_publisher(self.store)
        mode = native_mode()
        self._owns_policy_snapshot_publisher = publish_native_policy and mode in {"auto", "force", "shadow"}
        if self._owns_policy_snapshot_publisher:
            self.policy_snapshot_publisher.start()
        if wait_for_native_policy and mode in {"auto", "force"}:
            wait_until_ready = getattr(self.policy_snapshot_publisher, "wait_until_ready", None)
            if callable(wait_until_ready):
                _ = wait_until_ready(time.monotonic() + _NATIVE_POLICY_STARTUP_READY_TIMEOUT_SECONDS)

    @property
    def last_native_decision_receipt(self) -> dict[str, object] | None:
        """Return the receipt produced by the most recent native review."""

        return self._last_native_decision_receipt

    def _load_config(self, guard_home: Path, workspace: Path | None) -> GuardConfig:
        return load_guard_config(guard_home, workspace=workspace)

    def _review_raw_hook_native(
        self,
        *,
        payload: dict[str, object],
        harness: str,
        event: str,
        guard_home: Path,
        home_dir: Path,
        cwd: Path | None,
        source_ref_external_allowed: bool,
        observe_mode: bool,
        deadline: float | None,
        policy_snapshot: Mapping[str, object] | None = None,
    ) -> dict[str, object] | None:
        return review_raw_hook_native(
            payload=payload,
            harness=harness,
            event=event,
            guard_home=guard_home,
            home_dir=home_dir,
            cwd=cwd,
            source_ref_external_allowed=source_ref_external_allowed,
            observe_mode=observe_mode,
            deadline=deadline,
            policy_snapshot=policy_snapshot,
        )

    def _native_runtime_status(self) -> NativeRuntimeStatus:
        return native_runtime_status()

    def close(self) -> None:
        """Stop the publisher only when this worker started publication."""

        _ = self.close_contained()

    def close_contained(self) -> bool:
        """Confirm this worker's publisher has stopped before releasing ownership."""

        if self._owns_policy_snapshot_publisher:
            close_contained = getattr(self.policy_snapshot_publisher, "close_contained", None)
            if callable(close_contained):
                return close_contained() is not False
            self.policy_snapshot_publisher.close()
        return True

    def prepare_workspace_policy(
        self,
        workspace: Path | None = None,
        *,
        deadline: float | None = None,
    ) -> dict[str, object] | None:
        """Prepare an ACKed workspace policy before admitting a native hook.

        Workspace overlays are published asynchronously, so the first hook
        for a workspace must complete this same barrier used by normal hook
        evaluation. The barrier is always capped at the native readiness
        budget. Publishing workers fail closed when readiness is unavailable;
        non-publishing workers may reuse a still-valid resident-accepted snapshot.
        """

        if native_mode() not in {"auto", "force", "shadow"}:
            return None
        if self._publish_native_policy:
            register_workspace = getattr(self.policy_snapshot_publisher, "register_workspace", None)
            if callable(register_workspace):
                _ = register_workspace(workspace)
            self.policy_snapshot_publisher.start()
            if native_mode() in {"auto", "force"}:
                wait_until_ready = getattr(self.policy_snapshot_publisher, "wait_until_ready", None)
                last_error = getattr(self.policy_snapshot_publisher, "last_error", None)
                # A replacement resident can serve persisted policy before the
                # publisher confirms its new generation. Its restart-budget
                # lock can also be briefly held by a concurrent native client.
                # Await the fresh ACK within the existing deadline; unrelated
                # publication errors still fail immediately.
                transient_publication_error = (
                    isinstance(last_error, str) and last_error in _TRANSIENT_RESIDENT_PUBLICATION_ERRORS
                )
                no_publication_error = last_error is None or (isinstance(last_error, str) and not last_error.strip())
                if callable(wait_until_ready) and (transient_publication_error or no_publication_error):
                    readiness_deadline = time.monotonic() + _NATIVE_POLICY_READY_TIMEOUT_SECONDS
                    if deadline is not None:
                        readiness_deadline = min(readiness_deadline, deadline)
                    _ = wait_until_ready(readiness_deadline)
        current_snapshot_binding = getattr(self.policy_snapshot_publisher, "current_snapshot_binding", None)
        if callable(current_snapshot_binding):
            snapshot = current_snapshot_binding()
            if isinstance(snapshot, dict):
                return snapshot
        current_snapshot = getattr(self.policy_snapshot_publisher, "current_snapshot", None)
        if callable(current_snapshot):
            snapshot = current_snapshot()
            if isinstance(snapshot, dict):
                return snapshot
        if self._publish_native_policy:
            return None
        return acked_snapshot_binding_for_store(self.store)

    def _native_policy_snapshot(
        self,
        workspace: Path | None = None,
        *,
        deadline: float | None = None,
    ) -> dict[str, object] | None:
        """Return only the last resident-ACKed snapshot for native hooks."""

        return self.prepare_workspace_policy(workspace, deadline=deadline)

    def review_http_payload(
        self,
        *,
        payload: dict[str, object],
        params: Mapping[str, list[str]],
        default_harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None = None,
        claim_saved_approval: bool = True,
        claimed_saved_allow_hash: str | None = None,
        claimed_approval_request_id: str | None = None,
    ) -> dict[str, object]:
        """Review a hook HTTP payload and return harness JSON.

        ``auto`` and ``force`` require the native runtime. When native is
        unavailable or returns no result, protected PreToolUse requests deny.
        Acknowledged Watch and PostToolUse continue without claiming evaluated
        protection. Local inspection needs the same trusted decision boundary.
        ``off`` and ``shadow`` remain fail-safe without Python semantics.
        """
        self._last_native_decision_receipt = None
        harness = self._runtime_harness(params) or default_harness
        event_name = self._hook_event_name(payload)
        if (
            event_name == "Notification"
            and harness.strip().lower().replace("_", "-") == "claude-code"
            and str(payload.get("notification_type") or "") == "permission_prompt"
        ):
            return self._claude_permission_prompt_notification_response(payload)
        mode = native_mode()
        if mode in {"auto", "force"}:
            # Send even unknown or malformed event labels to Rust. The edge
            # returns no semantic result for unsupported events, which this
            # method turns into a deterministic deny/fail-safe response.
            # The concrete worker supplies the mixin host protocol, so bind
            # these methods through the worker rather than the mixin class.
            return self._review_native_edge(
                payload=payload,
                harness=harness,
                event_name=event_name,
                default_harness=default_harness,
                guard_home=guard_home,
                home_dir=home_dir,
                workspace=workspace,
                deadline=deadline,
                claim_saved_approval=claim_saved_approval,
                claimed_saved_allow_hash=claimed_saved_allow_hash,
                claimed_approval_request_id=claimed_approval_request_id,
            )
        mode_response = self._mode_surface_response(
            harness,
            event_name,
            mode,
            payload=payload,
            workspace=workspace,
            home_dir=home_dir,
            guard_home=guard_home,
        )
        if mode_response is not None:
            return self._apply_structured_unavailable_overlay(
                mode_response,
                harness=harness,
                event_name=event_name,
                guard_home=guard_home,
                workspace=workspace,
            )
        if event_name == "PreToolUse":
            return self._review_pre_tool_http(
                payload,
                harness=harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )
        post_response = self._review_post_tool_http(
            payload,
            harness=harness,
            default_harness=default_harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
        )
        return self._apply_structured_unavailable_overlay(
            post_response,
            harness=harness,
            event_name=event_name,
            guard_home=guard_home,
            workspace=workspace,
        )

    def _claude_permission_prompt_notification_response(
        self,
        payload: dict[str, object],
    ) -> dict[str, object]:
        """Present the pending Guard approval when Claude shows a permission prompt."""
        from ..cli._commands_shared import _now
        from ..cli.commands_support_claude_approval import (
            _claude_permission_prompt_additional_context,
            _claude_permission_prompt_system_message,
        )
        from ..cli.commands_support_hook_state import (
            _load_claude_permission_notice,
            _mark_claude_pending_permission_prompt_seen,
        )

        notice = _load_claude_permission_notice(self.store, payload)
        _mark_claude_pending_permission_prompt_seen(store=self.store, payload=payload, notice=notice)
        self.store.add_event(
            "claude/permission_prompt",
            {
                "session_id": payload.get("session_id"),
                "notification_type": payload.get("notification_type"),
                "tool_name": payload.get("tool_name"),
                "notice": notice or {},
            },
            _now(),
        )
        return {
            "systemMessage": _claude_permission_prompt_system_message(payload=payload, notice=notice),
            "hookSpecificOutput": {
                "hookEventName": "Notification",
                "additionalContext": _claude_permission_prompt_additional_context(notice),
            },
        }

    def _review_post_tool_http(
        self,
        payload: dict[str, object],
        *,
        harness: str,
        default_harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None,
    ) -> dict[str, object]:
        event_name = "PostToolUse"
        request = self._request_from_payload(
            payload,
            harness=harness,
            source_ref_external_allowed=default_harness.strip().lower().replace("_", "-") in {"pi", "omp"},
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
        )
        mode = native_mode()
        native_required = mode in {"auto", "force"}
        if native_required:
            policy_snapshot = self._native_policy_snapshot(workspace, deadline=deadline)
            recording_only = policy_snapshot is not None and policy_snapshot.get("mode") == "observe"
            response = review_post_tool_native(
                request,
                observe_mode=recording_only,
                policy_snapshot=policy_snapshot,
            )
            if response is None:
                self._record_post_tool_activity(
                    harness=harness,
                    payload=payload,
                    succeeded=hook_post_succeeded(event_name, payload),
                )
                return _post_tool_unavailable_response(
                    payload,
                    harness=harness,
                    reason_code="native_post_tool_unavailable",
                    workspace=workspace,
                    home_dir=home_dir,
                    guard_home=guard_home,
                )
        else:
            self._record_post_tool_activity(
                harness=harness,
                payload=payload,
                succeeded=hook_post_succeeded(event_name, payload),
            )
            reason_code = "native_hook_disabled" if mode == "off" else "native_shadow_diagnostic_disabled"
            return _post_tool_unavailable_response(
                payload,
                harness=harness,
                reason_code=reason_code,
                workspace=workspace,
                home_dir=home_dir,
                guard_home=guard_home,
            )

        self._record_post_tool_activity(
            harness=harness,
            payload=payload,
            succeeded=hook_post_succeeded(event_name, payload),
        )
        return harness_json_from_review_response(harness, event_name, response)

    def _record_post_tool_activity(
        self,
        *,
        harness: str,
        payload: Mapping[str, object],
        succeeded: bool,
    ) -> None:
        if self.activity_writer is not None:
            discovery_writer = getattr(self.activity_writer, "submit_composio_discovery", None)
            if callable(discovery_writer):
                with suppress(Exception):
                    discovery_writer(harness=harness, payload=payload, succeeded=succeeded)
            _ = self.activity_writer.submit_command_activity(
                harness=harness,
                event="PostToolUse",
                payload=payload,
                succeeded=succeeded,
            )
            return
        _ = record_post_hook_command_activity_best_effort(
            store=self.store,
            guard_home=self.guard_home,
            harness=harness,
            event="PostToolUse",
            payload=payload,
            succeeded=succeeded,
        )

    def _runtime_harness(self, params: Mapping[str, list[str]]) -> str | None:
        values = params.get("runtime-harness", [])
        if values and isinstance(values[-1], str) and values[-1].strip():
            return values[-1].strip()
        return None

    def _request_from_payload(
        self,
        payload: dict[str, object],
        *,
        harness: str,
        source_ref_external_allowed: bool,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        deadline: float | None = None,
    ) -> HookReviewRequest:
        return build_hook_review_request(
            payload,
            harness=harness,
            source_ref_external_allowed=source_ref_external_allowed,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
        )

    def _hook_event_name(self, payload: Mapping[str, object]) -> str:
        return runtime_hook_event_name(payload)


__all__ = [
    "HookWorker",
]
