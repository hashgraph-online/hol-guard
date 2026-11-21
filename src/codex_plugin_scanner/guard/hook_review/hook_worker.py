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

import os
import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast, final

from ..codex_hook_launch_runtime import hook_processes_contained
from ..config import load_guard_config
from ..hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY
from ..native_codex_binding_capture import CodexBindingCaptureWriter
from ..native_hook_adapter import hook_adapter_memo
from ..native_hook_edge import review_raw_hook_native
from ..native_payload_facts import native_hook_event
from ..native_policy_snapshot import get_native_policy_snapshot_publisher
from ..native_policy_snapshot_acked import acked_snapshot_binding_for_store as acked_snapshot_binding_for_store
from ..native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS, TRANSIENT_PUBLICATION_ERRORS
from ..native_runtime import NativeRuntimeStatus, native_runtime_status
from ..native_runtime_status_share import share_verified_runtime_status
from ..resident_evidence_dispatch import ResidentEvidenceDispatch, run_resident_evidence
from ..resident_route_counters import RouteCounterLog
from ..runtime.extension_control_runtime import current_extension_control_binding_digest
from .hook_worker_native import HookWorkerNativeMixin
from .hook_worker_readiness import prepare_workspace_policy
from .hook_worker_unavailable import unavailable_event_response

if TYPE_CHECKING:
    from ..config import GuardConfig
    from ..resident_evidence_drain import ResidentEvidenceDrain
    from ..store import GuardStore


class CommandActivityWriter(Protocol):
    def submit_post_tool_activity(
        self,
        *,
        harness: str,
        event: str,
        payload: Mapping[str, object],
    ) -> bool: ...


# Startup priming keeps the publish bound so a slow first publication never
# delays worker construction. Requests that arrive during a resident restart
# wait on the readiness bound instead, which needs a wider window everywhere:
# republication is slower on macOS and Windows, and Linux CI runners under
# parallel shard load miss the publish bound too.
_NATIVE_POLICY_STARTUP_READY_TIMEOUT_SECONDS = _PUBLISH_TIMEOUT_SECONDS
_NATIVE_POLICY_READY_TIMEOUT_SECONDS = 25.0
# Session setup uses this bounded window before any timed runtime hook starts.
WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS = _NATIVE_POLICY_READY_TIMEOUT_SECONDS
# The publisher retries these on its own: another writer re-committed the
# command-control authority, or a late renewal let the snapshot expire. A hook
# waits for that fresh ACK within its deadline instead of failing at once.
_TRANSIENT_RESIDENT_PUBLICATION_ERRORS = TRANSIENT_PUBLICATION_ERRORS | {"native_policy_snapshot_expired"}
# Harnesses whose PermissionRequest hook gets no decision, so the harness
# shows its own approval prompt. Each raises it only after its PreToolUse
# hook reviewed the same call.
_PERMISSION_PASSTHROUGH_HARNESSES = frozenset({"codex", "copilot", "devin", "zcode", "muse"})
# The Claude hook fields the resident's lifecycle answers read: the session,
# the prompt's kind and the tool it names.
_CLAUDE_LIFECYCLE_FIELDS = ("event_name", "session_id", "notification_type", "tool_name", "message", "title")
# The prompt copy when the resident cannot answer: it says Guard is holding the
# request, so an unreachable resident never leaves a prompt reading as though
# Guard allowed the action.
_CLAUDE_COPY_UNAVAILABLE = (
    "HOL Guard is holding this Claude request for review. The HOL Guard runtime could not render "
    "the full notice, so nothing in this prompt should be read as HOL Guard allowing the action."
)


@final
class HookWorker(HookWorkerNativeMixin):
    """Resident hook review worker for the daemon."""

    def __init__(
        self,
        *,
        store: GuardStore,
        workspace: Path | None = None,
        home_dir: Path | None = None,
        activity_writer: CommandActivityWriter | None = None,
        evidence_dispatch: ResidentEvidenceDispatch | None = None,
        capture_writer: CodexBindingCaptureWriter | None = None,
        wait_for_native_policy: bool = True,
        publish_native_policy: bool = True,
        start_native_policy: bool = True,
    ):
        self.store = store
        self.guard_home = store.guard_home
        self.activity_writer = activity_writer
        # Without one, evidence is recorded on the thread that answered the
        # hook, exactly as it was before the dispatch existed.
        self.evidence_dispatch = evidence_dispatch
        self.capture_writer = capture_writer
        self._publish_native_policy = publish_native_policy
        self._last_native_decision_receipt: dict[str, object] | None = None
        from ..route_metrics import RouteMetricsRecorder

        self.metrics = RouteMetricsRecorder()
        self.hook_counters = RouteCounterLog()
        self.policy_snapshot_publisher = get_native_policy_snapshot_publisher(self.store)
        # Resolve harness modules before a managed hook request starts
        # its deadline. This lookup grants no authority; native policy
        # readiness remains the enforcement barrier.
        from ..native_harness_ops import list_harnesses

        _ = list_harnesses()
        self._owns_policy_snapshot_publisher = publish_native_policy
        self._direct_evidence_drain: ResidentEvidenceDrain | None = None
        if start_native_policy:
            self.start_native_policy_publication(home_dir=home_dir, workspace=workspace)
        if wait_for_native_policy and start_native_policy:
            wait_until_ready = getattr(self.policy_snapshot_publisher, "wait_until_ready", None)
            if callable(wait_until_ready):
                _ = wait_until_ready(time.monotonic() + _NATIVE_POLICY_STARTUP_READY_TIMEOUT_SECONDS)

    def start_native_policy_publication(self, *, home_dir: Path | None = None, workspace: Path | None = None) -> None:
        """Starts publishing native policy, with its direct-lane lease and evidence drain.

        A worker built with ``start_native_policy=False`` publishes nothing
        until this runs, so its owner can build it early and start it once
        publishing is safe.
        """

        if not self._owns_policy_snapshot_publisher:
            return
        bind_daemon_home = getattr(self.policy_snapshot_publisher, "bind_direct_lane_daemon_home", None)
        if home_dir is not None and callable(bind_daemon_home):
            bind_daemon_home(home_dir)
        if workspace is not None:
            self.policy_snapshot_publisher.register_workspace(workspace)
        self._start_direct_evidence_drain()
        self.policy_snapshot_publisher.start()

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
        request_id: str | None = None,
        local_cli_rules: bool = False,
        observe_local_cli: bool = False,
        record_receipt: bool = False,
        structured_output_config: Mapping[str, object] | None = None,
        containment_sink: bool = False,
    ) -> dict[str, object] | None:
        runtime_status = self._native_runtime_status()
        store_path = getattr(self.store, "path", None)
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
            runtime_status=runtime_status,
            observe_local_cli=observe_local_cli,
            record_receipt=record_receipt,
            **({"request_id": request_id} if request_id is not None else {}),
            # The edge settles the daemon's custom extension rules and proves a
            # review's evidence; a launch resolves against the daemon's home and
            # environment.
            local_cli_rules=(
                {
                    "store_path": str(store_path),
                    "user_home": str(Path.home()),
                    "env": dict(os.environ),
                    "exact_action_control_digest": current_extension_control_binding_digest(),
                }
                if local_cli_rules and isinstance(store_path, Path)
                else None
            ),
            structured_output_config=structured_output_config,
            containment_sink=containment_sink,
        )

    def _native_runtime_status(self) -> NativeRuntimeStatus:
        current_runtime_status = getattr(self.policy_snapshot_publisher, "current_runtime_status", None)
        if callable(current_runtime_status):
            status = current_runtime_status()
            if status is not None:
                verified = cast(NativeRuntimeStatus, status)
                share_verified_runtime_status(verified)
                return verified
        return native_runtime_status()

    def close(self, *, deadline_monotonic: float | None = None) -> bool:
        """Stop the publisher only when this worker started publication."""

        return self.close_contained(deadline_monotonic=deadline_monotonic)

    def _start_direct_evidence_drain(self) -> None:
        # Direct answers are bound only while their evidence has a writer.
        enable = getattr(self.policy_snapshot_publisher, "enable_direct_evidence_drain", None)
        if self.activity_writer is None or not callable(enable):
            return
        from ..resident_evidence_drain import ResidentEvidenceDrain

        self._direct_evidence_drain = ResidentEvidenceDrain(self)
        enable(True)
        self._direct_evidence_drain.start()

    def _stop_direct_evidence_drain(self, *, deadline_monotonic: float | None = None) -> bool:
        drain = self._direct_evidence_drain
        if drain is None:
            return True
        # Close the lane first, then collect what the resident already queued.
        enable = getattr(self.policy_snapshot_publisher, "enable_direct_evidence_drain", None)
        if callable(enable):
            with suppress(Exception):
                enable(False)
        if deadline_monotonic is None:
            stopped = drain.stop()
        else:
            stopped = drain.stop(timeout_seconds=min(1.0, max(0.0, deadline_monotonic - time.monotonic())))
        if stopped is not True:
            return False
        self._direct_evidence_drain = None
        return True

    def close_contained(self, *, deadline_monotonic: float | None = None) -> bool:
        """Confirm this worker's publisher has stopped before releasing ownership."""

        if not self._stop_direct_evidence_drain(deadline_monotonic=deadline_monotonic):
            return False
        if self._owns_policy_snapshot_publisher:
            close_contained = getattr(self.policy_snapshot_publisher, "close_contained", None)
            if not callable(close_contained):
                close_contained = self.policy_snapshot_publisher.close
            closed = (
                close_contained()
                if deadline_monotonic is None
                else close_contained(deadline_monotonic=deadline_monotonic)
            )
            if closed is False:
                return False
        # A helper the publisher cancelled may sit in quarantine after a failed
        # kill or cleanup; keep ownership until every quarantined helper is reaped.
        return hook_processes_contained(deadline_monotonic=deadline_monotonic)

    def prepare_workspace_policy(
        self, workspace: Path | None = None, *, deadline: float | None = None
    ) -> dict[str, object] | None:
        return prepare_workspace_policy(self, workspace, deadline=deadline, now=time.monotonic())

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
        event_name: str | None = None,
        claim_saved_approval: bool = True,
        claimed_saved_allow_hash: str | None = None,
        claimed_approval_request_id: str | None = None,
    ) -> dict[str, object]:
        """Review a hook HTTP payload and return harness JSON.

        The native runtime is required. When it is unavailable or returns no
        result, protected PreToolUse requests deny. Acknowledged Watch and
        PostToolUse continue without claiming evaluated protection. Local
        inspection needs the same trusted decision boundary.
        """
        # Keep caller metadata intact across the resident boundary. The outer
        # hook bridge stamps this field; a direct daemon caller has no trusted
        # caller context and must not be replaced with the daemon environment.
        payload = dict(payload)
        payload.setdefault(HOOK_EXECUTION_ENVIRONMENT_KEY, None)
        self._last_native_decision_receipt = None
        harness = self._runtime_harness(params) or default_harness
        event_name = event_name or self._hook_event_name(payload, deadline)
        if event_name is None and harness.strip().lower().replace("_", "-") == "claude-code":
            candidate = payload.get("hook_event_name")
            if isinstance(candidate, str) and candidate in {"PermissionRequest", "Stop", "Notification", "PostToolUse"}:
                event_name = candidate
        if event_name is None:
            return unavailable_event_response(
                self,
                payload=payload,
                harness=harness,
                guard_home=guard_home,
                workspace=workspace,
                deadline=deadline,
            )
        if harness.strip().lower().replace("_", "-") == "claude-code":
            answered = self._claude_lifecycle_response(event_name, payload)
            if answered is not None:
                return answered
        if (
            event_name in {"PermissionRequest", "copilotPermissionRequest"}
            and harness.strip().lower().replace("_", "-") in _PERMISSION_PASSTHROUGH_HARNESSES
        ):
            # These harnesses ask this only for a call their PreToolUse hook
            # already sent to Guard. A deny here would refuse every approval
            # the harness asks for, so the decision stays with the harness's
            # own approval prompt.
            return {"hookSpecificOutput": {"hookEventName": event_name}}
        if event_name == "PreToolUse" and harness.strip().lower() == "cursor":
            from .cursor_shell_route import cursor_shell_route_response

            routed = cursor_shell_route_response(
                self,
                payload=payload,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
                deadline=deadline,
            )
            if routed is not None:
                return routed
        # Send even unknown or malformed event labels to Rust. The edge
        # returns no semantic result for unsupported events, which this
        # method turns into a deterministic deny/fail-safe response.
        # The concrete worker supplies the mixin host protocol, so bind
        # these methods through the worker rather than the mixin class.
        with hook_adapter_memo(guard_home):
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

    def _claude_lifecycle_response(
        self,
        event_name: str,
        payload: dict[str, object],
    ) -> dict[str, object] | None:
        """Claude Code's answer for a lifecycle hook, or ``None`` for the edge.

        A permission prompt or dialog is answered by one resident call that
        reads the session's pending Guard review, marks it seen and records
        the prompt. ``Stop`` drops the session's unanswered prompts, so the
        next turn reviews the call again instead of inheriting a block nobody
        chose, and the same call returns its answer; a runtime too old to
        return one leaves ``Stop`` to the edge. A ``PostToolUse`` that answers
        the HOL Guard approval question saves that answer.
        """
        if event_name == "PostToolUse":
            # The CLI helper modules resolve shared names through the command
            # support registry, which a resident built in process has not loaded.
            from ..cli import commands_support  # noqa: F401
            from ..cli.commands_support_claude_approval import _settle_claude_guard_question

            return None if _settle_claude_guard_question(self.store, payload) is None else {}
        if not (
            event_name == "PermissionRequest"
            or event_name == "Stop"
            or (event_name == "Notification" and str(payload.get("notification_type") or "") == "permission_prompt")
        ):
            return None
        from ..cli._commands_shared import _now
        from ..cli.commands_support_runtime_artifacts import _optional_string
        from ..native_hook_authority_state import (
            HOOK_AUTHORITY_STATE_CLAUDE_LIFECYCLE_FEATURE,
            hook_authority_state,
            object_field,
        )

        reply = hook_authority_state(
            self.store,
            "claude_lifecycle",
            now=_now(),
            required_feature=HOOK_AUTHORITY_STATE_CLAUDE_LIFECYCLE_FEATURE,
            session_id=_optional_string(payload.get("session_id")),
            payload={
                "event_name": event_name,
                **{
                    name: payload[name] for name in _CLAUDE_LIFECYCLE_FIELDS if name != "event_name" and name in payload
                },
            },
        )
        answered = object_field(reply, "harness_response")
        if answered is not None or event_name == "Stop":
            return answered
        if event_name == "PermissionRequest":
            # Without the resident there is no pending review to present, so
            # the dialog stays Claude's own, as for a session with none.
            return {
                "guard_permission_passthrough": True,
                "hookSpecificOutput": {"hookEventName": "PermissionRequest"},
            }
        return {
            "systemMessage": _CLAUDE_COPY_UNAVAILABLE,
            "hookSpecificOutput": {"hookEventName": "Notification", "additionalContext": _CLAUDE_COPY_UNAVAILABLE},
        }

    def _record_post_tool_activity(
        self,
        *,
        harness: str,
        event: str,
        payload: Mapping[str, object],
    ) -> None:
        # A worker built without the resident writer (a qualification probe,
        # a bound Bash sink) never answers a post-tool call it should record.
        writer = self.activity_writer
        if writer is None:
            return

        # Keep the writer round trip out of the hook's decision budget.
        def record() -> None:
            _ = writer.submit_post_tool_activity(harness=harness, event=event, payload=payload)

        run_resident_evidence(self, record)

    def _runtime_harness(self, params: Mapping[str, list[str]]) -> str | None:
        values = params.get("runtime-harness", [])
        if values and isinstance(values[-1], str) and values[-1].strip():
            return values[-1].strip()
        return None

    def _hook_event_name(self, payload: Mapping[str, object], deadline: float | None = None) -> str | None:
        # Event identity is a resident-owned fact. A missing fact stays
        # unavailable so callers can shape an outage response separately. An
        # explicit wire label still lets the caller reach that bounded
        # fail-safe path when the resident cannot answer the fact lookup.
        event = native_hook_event(payload, self.store.guard_home, deadline=deadline)
        if event is not None:
            return event
        from .hook_availability_policy import canonical_hook_event_name

        for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return canonical_hook_event_name(payload)
        return None


__all__ = [
    "HookWorker",
]
