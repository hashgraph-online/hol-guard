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
  cannot complete, PostToolUse continues; PreToolUse uses the emergency-safe
  floor. Explicit ``off`` is a fail-safe disablement in production; only a
  test-injected oracle may run.
- Supported generic PreToolUse is decided by Rust. Native failure uses the
  mechanical emergency-safe action-class floor: local inspection may continue,
  while mutating, network, secret, destructive, and uncertain actions pause.
  Explicit off/shadow have no production semantic fallback. Native block
  results stay mechanical. Native review pauses the tool and queues an
  approval-center request; it never escapes to the Python semantic CLI path.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Protocol, cast, final

from ..cli.commands_support_command_activity import (
    hook_post_succeeded,
    record_post_hook_command_activity_best_effort,
)
from ..config import load_guard_config
from ..native_hook_edge import review_raw_hook_native
from ..native_mode import python_oracle_enabled, python_oracle_surface_enabled
from ..native_policy_snapshot import get_native_policy_snapshot_publisher
from ..native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS
from ..native_policy_snapshot_storage import acked_snapshot_binding_for_store
from ..native_pretool import review_pre_tool_native
from ..native_route_receipt import record_python_semantic_hook_route
from ..native_runtime import NativeRuntimeStatus, native_mode, native_runtime_status, review_post_tool_native
from ..runtime.hook_review_types import (
    HookOutputSummary,
    HookPayloadKind,
    HookReviewRequest,
    HookReviewResponse,
    HookSourceFileRef,
)
from .hook_availability_policy import availability_harness_response
from .hook_request_parsing import (
    build_hook_review_request,
    parse_output_summary,
    parse_source_ref,
    payload_kind,
    runtime_hook_event_name,
)
from .hook_worker_native import HookWorkerNativeMixin, HookWorkerUnsupported, PythonOracle
from .hook_worker_responses import (
    harness_json_from_review_response,
)

if TYPE_CHECKING:
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


_NATIVE_POLICY_READY_TIMEOUT_SECONDS = _PUBLISH_TIMEOUT_SECONDS


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

    # The callback is installed by pytest's explicit differential-oracle
    # fixture. Production has no callback and therefore cannot construct a
    # Python semantic reviewer from this worker.
    _test_python_oracle_factory: ClassVar[Callable[[HookWorker], PythonOracle] | None] = None

    def __init__(
        self,
        *,
        store: GuardStore,
        activity_writer: CommandActivityWriter | None = None,
        wait_for_native_policy: bool = True,
    ):
        self.store = store
        self.guard_home = store.guard_home
        self.activity_writer = activity_writer
        self._last_native_decision_receipt: dict[str, object] | None = None
        self._python_oracle: Callable[[HookReviewRequest], HookReviewResponse] | None = None
        self._python_oracle_object: PythonOracle | None = None
        from .hook_metrics import HookMetricsRecorder

        self.metrics = HookMetricsRecorder()
        if python_oracle_enabled():
            factory = type(self)._test_python_oracle_factory
            if callable(factory):
                oracle = factory(self)
                review = getattr(oracle, "review", None)
                if callable(review):
                    self._python_oracle_object = oracle
                    self._python_oracle = cast(Callable[[HookReviewRequest], HookReviewResponse], review)
        self.policy_snapshot_publisher = get_native_policy_snapshot_publisher(self.store)
        mode = native_mode()
        if mode in {"auto", "force", "shadow"}:
            self.policy_snapshot_publisher.start()
        if wait_for_native_policy and mode in {"auto", "force"}:
            wait_until_ready = getattr(self.policy_snapshot_publisher, "wait_until_ready", None)
            if callable(wait_until_ready):
                _ = wait_until_ready(time.monotonic() + _NATIVE_POLICY_READY_TIMEOUT_SECONDS)

    @property
    def test_oracle(self) -> PythonOracle | None:
        """Expose the injected differential oracle to test fixtures only."""

        return self._python_oracle_object

    @property
    def last_native_decision_receipt(self) -> dict[str, object] | None:
        """Return the receipt produced by the most recent native review."""

        return self._last_native_decision_receipt

    def _load_config(self, guard_home: Path, workspace: Path | None):
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

    def _review_pre_tool_native(
        self,
        command: str,
        *,
        guard_home: Path,
        cwd: Path | None,
        home_dir: Path | None,
    ) -> dict[str, object] | None:
        return review_pre_tool_native(command, guard_home=guard_home, cwd=cwd, home_dir=home_dir)

    def _native_runtime_status(self) -> NativeRuntimeStatus:
        return native_runtime_status()

    def close(self) -> None:
        """Stop the asynchronous native policy publisher with the worker."""

        self.policy_snapshot_publisher.close()

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
        budget. A timeout or a competing publisher still reuses a durable
        ACKed cache when one exists; otherwise callers admit emergency-safe
        inspection or pause high-impact actions.
        """

        if native_mode() not in {"auto", "force", "shadow"}:
            return None
        register_workspace = getattr(self.policy_snapshot_publisher, "register_workspace", None)
        if callable(register_workspace):
            _ = register_workspace(workspace)
        self.policy_snapshot_publisher.start()
        if native_mode() in {"auto", "force"}:
            wait_until_ready = getattr(self.policy_snapshot_publisher, "wait_until_ready", None)
            last_error = getattr(self.policy_snapshot_publisher, "last_error", None)
            if callable(wait_until_ready) and not (isinstance(last_error, str) and last_error.strip()):
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
    ) -> dict[str, object]:
        """Review a hook HTTP payload and return harness JSON.

        ``auto`` and ``force`` require the native runtime. When native is
        unavailable or returns no result, high-impact PreToolUse pauses.
        PostToolUse continues so the turn does not freeze. Emergency-safe
        local inspection continues with an explicit degraded reason code.
        ``off`` and ``shadow`` can use only an explicit test oracle;
        production requests remain fail-safe.
        """
        self._last_native_decision_receipt = None
        harness = self._runtime_harness(params) or default_harness
        event_name = self._hook_event_name(payload)
        mode = native_mode()
        if mode in {"auto", "force"}:
            # Send even unknown or malformed event labels to Rust. The edge
            # returns no semantic result for unsupported events, which this
            # method turns into a deterministic deny/fail-safe response.
            return self._review_native_edge(
                payload=payload,
                harness=harness,
                event_name=event_name,
                default_harness=default_harness,
                guard_home=guard_home,
                home_dir=home_dir,
                workspace=workspace,
                deadline=deadline,
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
            return mode_response
        if event_name == "PreToolUse":
            return self._review_pre_tool_http(
                payload,
                harness=harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )
        return self._review_post_tool_http(
            payload,
            harness=harness,
            default_harness=default_harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
        )

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
        elif self._python_oracle is not None and python_oracle_surface_enabled(mode):
            record_python_semantic_hook_route()
            try:
                response = self._python_oracle(request)
            except Exception:
                self._record_post_tool_activity(
                    harness=harness,
                    payload=payload,
                    succeeded=hook_post_succeeded(event_name, payload),
                )
                return _post_tool_unavailable_response(
                    payload,
                    harness=harness,
                    reason_code="python_oracle_exception",
                    workspace=workspace,
                    home_dir=home_dir,
                    guard_home=guard_home,
                )
            if mode == "shadow":
                with suppress(Exception):
                    _ = review_post_tool_native(
                        request,
                        observe_mode=response.observe_mode,
                        policy_snapshot=self._native_policy_snapshot(workspace, deadline=deadline),
                    )
        elif python_oracle_enabled() and python_oracle_surface_enabled(mode):
            raise HookWorkerUnsupported("explicit test oracle is not installed in this process")
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

    def _payload_kind(self, payload: Mapping[str, object]) -> HookPayloadKind:
        return payload_kind(payload)

    def _parse_output_summary(self, payload: Mapping[str, object]) -> HookOutputSummary | None:
        return parse_output_summary(payload)

    def _parse_source_ref(self, payload: Mapping[str, object]) -> HookSourceFileRef | None:
        return parse_source_ref(payload)


__all__ = [
    "HookWorker",
    "HookWorkerUnsupported",
]
