"""The daemon's runtime hook routes: ``POST /v1/hooks/<harness>`` and its readiness check.

A hook is admitted under its deadline and the review scheduler's capacity,
then reviewed by the resident hook worker; anything that cannot finish safely
answers with the harness's fail-safe response. The handler that hosts these
routes supplies the request (``headers``, ``path``, ``command``), the reply
(``_write_json``), the audit (``_record_bounded_denial_event``) and the server
state (``_daemon_server``).
"""

# pyright: reportUninitializedInstanceVariable=false

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from ..native_directory_trust import (
    UNAVAILABLE_REASON as _DIRECTORY_TRUST_UNAVAILABLE,
)
from ..native_directory_trust import (
    DirectoryTrustCandidate,
    DirectoryTrustVerdict,
    NativeDirectoryTrustError,
    native_directory_trust,
)
from .hook_managed_install_state import _hook_harness_is_unmanaged
from .hook_policy_admission import prepare_native_hook_policy
from .hook_worker import WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS
from .runtime_hook_deadline import PROMPT_ADMISSION_SECONDS, RuntimeHookDeadline, remaining_hint_from_payload
from .runtime_hook_scheduler import RuntimeHookAdmissionReason, RuntimeHookLane

_RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS = 3.0
_RUNTIME_WORKSPACE_READINESS_TIMEOUT_SECONDS = WORKSPACE_POLICY_READINESS_TIMEOUT_SECONDS


class _HookPathValidationError(ValueError):
    def __init__(self, parameter: str, reason: str) -> None:
        self.parameter = parameter
        self.reason = reason
        parameter_slug = parameter.replace("-", "_")
        super().__init__(f"invalid_hook_{parameter_slug}_path")
        self.code = f"invalid_hook_{parameter_slug}_path"


# One request spells the same directory several ways -- the query string, the
# payload, the exec command's own working directory -- and each spelling is
# labelled apart so their verdicts cannot collide. A caller still sees the
# parameter the route has always reported, whichever spelling was refused.
_REPORTED_HOOK_PARAMETER = {
    "exec-workdir": "workspace",
    "workspace-payload": "workspace",
    "workspace-query": "workspace",
}


def _reported_hook_parameter(parameter: str) -> str:
    """The name a rejection of this candidate is reported under."""

    return _REPORTED_HOOK_PARAMETER.get(parameter, parameter)


class _HookDirectories:
    """The directories one hook request named, as the native owner settled them.

    Every candidate is asked for in a single call, so the handler reads its
    verdicts back in whatever order the route needs without paying for a
    round trip per path. A parameter the request did not carry has no verdict
    and reads as `None`, which is what an absent directory meant before.
    """

    def __init__(self, verdicts: Sequence[DirectoryTrustVerdict]) -> None:
        self._verdicts = {verdict.parameter: verdict for verdict in verdicts}

    def require(self, parameter: str) -> str | None:
        """The settled path for one candidate, or `None` where it named none."""

        verdict = self._verdicts.get(parameter)
        if verdict is None:
            return None
        if verdict.reason is not None:
            raise _HookPathValidationError(_reported_hook_parameter(parameter), verdict.reason)
        return verdict.path


def _runtime_hook_remaining_hint(payload: dict[str, object]) -> float:
    hint = remaining_hint_from_payload(payload, pop=True)
    return _RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS if hint is None else hint


class _RuntimeHookRoutes:
    """Admits, reviews and answers runtime hooks for the handler hosting them."""

    headers: Any
    path: str
    command: str
    request: Any

    if TYPE_CHECKING:

        def _daemon_server(self) -> Any: ...

        def _write_json(
            self,
            payload: dict[str, Any],
            *,
            status: int = 200,
            extra_headers: dict[str, str] | None = None,
        ) -> None: ...

        def _record_bounded_denial_event(self, event_name: str, payload: dict[str, object]) -> None: ...

        @staticmethod
        def _optional_string(value: object) -> str | None: ...

    def _handle_hook_readiness(
        self,
        payload: dict[str, object],
        query: str,
        *,
        default_harness: str,
    ) -> None:
        """Prepare the active workspace before a host's timed hook starts.

        This route is deliberately separate from semantic hook review. It gives
        the native publisher and isolated worker the existing setup budget so a
        first tool call does not spend its short host deadline on cold startup.
        """

        params = parse_qs(query)
        workspace_candidate = self._hook_workspace_spelling(
            params.get("workspace", [None])[-1] or payload.get("workspace") or payload.get("cwd")
        )
        try:
            guard_home_candidate = self._optional_string(params.get("guard-home", [None])[-1])
            _ = self._settled_hook_directories(("guard-home", guard_home_candidate)).require("guard-home")
            # An unmanaged harness is ready without a workspace, so it is not
            # held behind settling one it will never use.
            if _hook_harness_is_unmanaged(self._daemon_server(), default_harness):
                self._write_json(
                    {"ready": True, "native_required": False, "workspace_acknowledged": False, "worker_ready": True},
                    extra_headers={"Cache-Control": "no-store"},
                )
                return
            workspace = self._settled_hook_directories(("workspace", workspace_candidate, "hook-workspace")).require(
                "workspace"
            )
        except _HookPathValidationError as error:
            self._record_hook_path_rejection(parameter=error.parameter, reason=error.reason)
            self._write_json(
                {"ready": False, "reason_code": f"invalid_{error.parameter.replace('-', '_')}"},
                status=400,
                extra_headers={"Cache-Control": "no-store"},
            )
            return
        if workspace is None:
            self._write_json(
                {"ready": False, "reason_code": "workspace_required"},
                status=400,
                extra_headers={"Cache-Control": "no-store"},
            )
            return

        daemon_server = self._daemon_server()
        readiness_deadline = time.monotonic() + _RUNTIME_WORKSPACE_READINESS_TIMEOUT_SECONDS
        try:
            prepared_policy = daemon_server.hook_worker.prepare_workspace_policy(
                Path(workspace),
                deadline=readiness_deadline,
            )
        except Exception:
            daemon_server.diagnostics.record_exception("native_workspace_readiness_failed")
            prepared_policy = None
        if not isinstance(prepared_policy, dict):
            self._write_json(
                {"ready": False, "reason_code": "native_policy_not_ready"},
                status=503,
                extra_headers={"Cache-Control": "no-store"},
            )
            return

        self._write_json(
            {
                "ready": True,
                "native_required": True,
                "native_route": "native_resident",
                "workspace_acknowledged": True,
                "worker_ready": True,
            },
            extra_headers={"Cache-Control": "no-store"},
        )

    def _handle_runtime_hook(self, payload: dict[str, object], query: str, *, default_harness: str) -> None:
        from .hook_direct_counters import note_hook_received
        from .hook_direct_pi_transport import pi_direct_answer
        from .hook_request_parsing import (
            HookPayloadReferenceError,
            hook_payload_reference_size,
            runtime_hook_event_name,
        )

        prompt_event = runtime_hook_event_name(payload) == "UserPromptSubmit"
        admission_seconds = PROMPT_ADMISSION_SECONDS if prompt_event else _RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS
        transport_deadline = self._daemon_server().request_deadline(self.request, admission_seconds)
        params = parse_qs(query)
        # Diagnostics only: a count by the harness the worker reviews (the
        # `runtime-harness` override first), and the reason a bridge names
        # for the resident not answering, before anything is judged.
        note_hook_received(
            getattr(self._daemon_server(), "hook_worker", None),
            self._optional_string(params.get("runtime-harness", [None])[-1]) or default_harness,
            self.headers.get("X-Guard-Direct-Miss"),
        )
        hint_missing = "guard_remaining_seconds" not in payload and "guard_remaining_ms" not in payload
        hook_deadline = RuntimeHookDeadline.for_admission(
            _runtime_hook_remaining_hint(payload),
            hint_missing=hint_missing,
            prompt_event=prompt_event,
            admission_seconds=admission_seconds,
            transport_deadline=transport_deadline,
        )
        payload = {key: value for key, value in payload.items() if key != "hook_env"}
        daemon_server = self._daemon_server()
        # Oh My Pi has no bridge to ask the resident first, so ask it here.
        # The raw `home` query goes with the raw workspace: the resident
        # settles both against the lane it bound, and a home it cannot settle
        # defers to the daemon path below, which refuses and audits it. Asking
        # the runtime to settle directories first would spend a round trip per
        # hook on the answer path, where nothing here reads the result.
        #
        # A `guard-home` query is the exception, because the lane never sends
        # it: it answers out of the home it bound, so a request naming another
        # Guard home would be answered without that claim being refused or
        # audited. Spelling it the same way as this daemon's own home is the
        # only claim the lane may answer, and this comparison costs no round
        # trip. A spelling that merely looks different -- a link, a relative
        # path -- is not refused here; it goes down the daemon path, which
        # settles it properly and refuses or admits it there.
        if self._hook_guard_home_query_is_this_home(params, daemon_server):
            direct_response = pi_direct_answer(
                getattr(daemon_server, "hook_worker", None),
                default_harness=default_harness,
                params=params,
                payload=payload,
                home_dir=self._optional_string(params.get("home", [None])[-1]),
                deadline=hook_deadline.expires_at,
            )
            if direct_response is not None:
                self._write_json(direct_response)
                return

        try:
            action_workdir_provided, action_workdir_spelling = self._runtime_hook_exec_command_workdir(payload)
            # One call settles every directory this request named, including
            # each spelling of the workspace; the verdicts are still read in
            # the order the route rejects in, and a spelling the route never
            # reaches is never held against it.
            directories = self._settled_hook_directories(
                ("home", self._optional_string(params.get("home", [None])[-1])),
                ("guard-home", self._optional_string(params.get("guard-home", [None])[-1])),
                ("exec-workdir", action_workdir_spelling, "exec-workdir"),
                ("workspace-payload", self._hook_workspace_spelling(payload.get("cwd")), "hook-workspace"),
                (
                    "workspace-query",
                    self._hook_workspace_spelling(params.get("workspace", [None])[-1]),
                    "hook-workspace",
                ),
                deadline_monotonic=hook_deadline.expires_at,
            )
            home_dir = directories.require("home")
            guard_home = directories.require("guard-home")
            action_workdir = directories.require("exec-workdir")
            if action_workdir_provided and action_workdir is None:
                raise _HookPathValidationError("workspace", "invalid_action_workdir")
            workspace = (
                action_workdir or directories.require("workspace-payload") or directories.require("workspace-query")
            )
        except _HookPathValidationError as error:
            # The Rust edge still receives the complete raw payload. Use
            # daemon-owned metadata when an optional caller context is
            # missing or invalid; never turn metadata rejection into a
            # Python semantic/source-ref fallback.
            self._record_hook_path_rejection(parameter=error.parameter, reason=error.reason)
            home_dir = str(daemon_server.home_dir)
            guard_home = str(daemon_server.store.guard_home)
            workspace = None

        if not prepare_native_hook_policy(
            self, daemon_server, payload, params, default_harness, workspace, hook_deadline.expires_at
        ):
            return

        runtime_harness = self._optional_string(params.get("runtime-harness", [None])[-1])
        capacity_harness = daemon_server.canonical_hook_capacity_harness(
            (runtime_harness or default_harness).strip().lower().replace("_", "-")
        )
        try:
            referenced_payload_bytes = hook_payload_reference_size(
                payload,
                guard_home=daemon_server.store.guard_home,
                deadline_monotonic=hook_deadline.expires_at,
            )
            payload_bytes = (
                referenced_payload_bytes
                if referenced_payload_bytes is not None
                else self._runtime_hook_payload_size(payload)
            )
        except HookPayloadReferenceError as error:
            daemon_server.hook_worker.metrics.record_failure(
                stage="server",
                exception_type=type(error).__name__,
            )
            self._write_json(
                self._runtime_hook_fail_safe_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason="HOL Guard could not authenticate the local hook payload.",
                    reason_code="invalid_hook_payload_reference",
                )
            )
            return

        byte_reservation, reservation_reason = daemon_server.runtime_hook_scheduler.reserve_bytes(
            payload_bytes=payload_bytes,
            deadline=hook_deadline.expires_at,
        )
        if byte_reservation is None:
            self._record_hook_capacity_rejection(daemon_server, capacity_harness)
            self._write_json(
                self._runtime_hook_capacity_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason_code=reservation_reason,
                )
            )
            return
        with byte_reservation:
            admission = daemon_server.runtime_hook_scheduler.acquire(
                harness=capacity_harness,
                client_key=self._runtime_hook_client_key(payload, workspace),
                lane=self._runtime_hook_lane(payload),
                payload_bytes=payload_bytes,
                deadline=hook_deadline,
                byte_reservation=byte_reservation,
            )
            if admission.permit is None:
                self._record_hook_capacity_rejection(daemon_server, capacity_harness)
                self._write_json(
                    self._runtime_hook_capacity_response(
                        payload,
                        params,
                        default_harness=default_harness,
                        reason_code=admission.reason_code,
                    )
                )
                return
        with daemon_server.hook_capacity_lock:
            daemon_server.active_hook_requests += 1
            daemon_server.hook_harness_active[capacity_harness] = (
                daemon_server.hook_harness_active.get(capacity_harness, 0) + 1
            )
        try:
            with admission.permit:
                self._execute_runtime_hook(
                    payload,
                    params,
                    default_harness=default_harness,
                    home_dir=home_dir,
                    guard_home=guard_home,
                    workspace=workspace,
                    deadline=hook_deadline.expires_at,
                    release_capacity=admission.permit.release,
                )
        finally:
            with daemon_server.hook_capacity_lock:
                daemon_server.active_hook_requests -= 1
                daemon_server.hook_harness_active[capacity_harness] -= 1

    @staticmethod
    def _runtime_hook_lane(payload: Mapping[str, object]) -> RuntimeHookLane:
        from .hook_worker import runtime_hook_event_name

        event = runtime_hook_event_name(payload).lower().replace("_", "").replace("-", "")
        if event in {"pretooluse", "permissionrequest", "userpromptsubmit", "userpromptsubmitted"}:
            return "decision"
        return "content-security"

    @staticmethod
    def _runtime_hook_client_key(payload: Mapping[str, object], workspace: str | None) -> str:
        session = next(
            (
                payload.get(key)
                for key in ("session_id", "conversation_id", "thread_id")
                if isinstance(payload.get(key), str) and payload.get(key)
            ),
            "",
        )
        material = f"{workspace or ''}\0{session}"
        return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:32]

    @staticmethod
    def _runtime_hook_payload_size(payload: Mapping[str, object]) -> int:
        return len(
            json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )

    @staticmethod
    def _record_hook_capacity_rejection(
        daemon_server: Any,
        capacity_harness: str,
    ) -> None:
        with daemon_server.hook_capacity_lock:
            daemon_server.rejected_hook_requests += 1
            daemon_server.hook_harness_rejected[capacity_harness] = (
                daemon_server.hook_harness_rejected.get(capacity_harness, 0) + 1
            )

    def _runtime_hook_capacity_response(
        self,
        payload: Mapping[str, object],
        params: Mapping[str, list[str]],
        *,
        default_harness: str,
        reason_code: RuntimeHookAdmissionReason | None = None,
    ) -> dict[str, object]:
        resolved_reason_code = reason_code or "daemon_hook_queue_capacity"
        if resolved_reason_code == "daemon_hook_deadline_exhausted":
            reason = "HOL Guard could not complete local review within the hook deadline. Retry this action."
        else:
            reason = "HOL Guard is safely queueing the maximum local review workload. Retry this action."
        return self._runtime_hook_fail_safe_response(
            payload,
            params,
            default_harness=default_harness,
            reason=reason,
            reason_code=resolved_reason_code,
        )

    def _runtime_hook_fail_safe_response(
        self,
        payload: Mapping[str, object],
        params: Mapping[str, list[str]],
        *,
        default_harness: str,
        reason: str,
        reason_code: str,
    ) -> dict[str, object]:
        runtime_harness = self._optional_string(params.get("runtime-harness", [None])[-1])
        harness = (runtime_harness or default_harness).strip().lower().replace("_", "-")
        event = self._optional_string(payload.get("hook_event_name", payload.get("event"))) or "PreToolUse"
        from .hook_availability_policy import availability_harness_response

        return availability_harness_response(
            harness=harness,
            event_name=event,
            reason_code=reason_code,
            reason=reason,
        )

    def _execute_runtime_hook(
        self,
        payload: dict[str, object],
        params: Mapping[str, list[str]],
        *,
        default_harness: str,
        home_dir: str | None,
        guard_home: str | None,
        workspace: str | None,
        deadline: float | None = None,
        release_capacity: Callable[[], None] | None = None,
    ) -> None:
        from contextlib import nullcontext

        from ..sqlite_tuning import sqlite_operation_deadline

        with sqlite_operation_deadline(deadline) if deadline is not None else nullcontext():
            result = self._handle_runtime_hook_fast(
                payload,
                params,
                default_harness=default_harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
                deadline=deadline,
            )
            if result is None:
                result = self._runtime_hook_fail_safe_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason="HOL Guard could not complete the native hook decision safely.",
                    reason_code="native_hook_worker_unavailable",
                )
            # A review that finished late still finished: the answer carries the
            # same decision the native edge would have sent on time, so send it
            # rather than a block. The client owns the real timeout -- it stops
            # waiting on its own clock and ignores whatever arrives after -- and
            # discarding a completed decision here only turns a slow host into a
            # blocked one, which is how a cold or contended machine ends up
            # refusing `grep`. The deadline still bounds the work itself: it
            # caps storage waits and the native edge's own evaluation, and a
            # review that produces nothing fails safe above.
        # The decision is final. Free its review slot before the answer is
        # sent: a client holding its answer must never see the slot still
        # busy, and a slow reader must not occupy review capacity.
        if release_capacity is not None:
            release_capacity()
        self._write_json(result)

    def _handle_runtime_hook_fast(
        self,
        payload: dict[str, object],
        params: Mapping[str, list[str]],
        *,
        default_harness: str,
        home_dir: str | None,
        guard_home: str | None,
        workspace: str | None,
        deadline: float | None,
    ) -> dict[str, object] | None:
        """Review through the resident hook worker; failures deny and never reach Python semantics."""
        from contextlib import nullcontext

        from ..sqlite_tuning import sqlite_operation_deadline

        daemon_server = self._daemon_server()
        effective_home_dir = Path(home_dir) if home_dir is not None else daemon_server.home_dir
        effective_guard_home = Path(guard_home) if guard_home is not None else daemon_server.store.guard_home

        # Keep failure rendering on the same storage clock as direct review.
        with sqlite_operation_deadline(deadline) if deadline is not None else nullcontext():
            try:
                worker = daemon_server.hook_worker
                return worker.review_http_payload(
                    payload=payload,
                    params=params,
                    default_harness=default_harness,
                    home_dir=effective_home_dir,
                    guard_home=effective_guard_home,
                    workspace=Path(workspace) if workspace else None,
                    deadline=deadline,
                )
            except Exception as error:
                # Fail safe: deny/block; there is no Python semantic fallback.
                self._daemon_server().hook_worker.metrics.record_failure(
                    stage="server",
                    exception_type=type(error).__name__,
                )
                return self._runtime_hook_fail_safe_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason="HOL Guard could not complete local hook review safely.",
                    reason_code="daemon_worker_exception",
                )

    def _hook_guard_home_query_is_this_home(
        self,
        params: Mapping[str, list[str]],
        daemon_server: object,
    ) -> bool:
        """Whether a `guard-home` query, if one was sent, names this daemon's home.

        Answering from the direct lane skips settling directories, so a claim
        about which Guard home a request belongs to has nothing to check it.
        Naming no home at all claims nothing and is fine; naming this one is
        the claim the lane is allowed to answer. Everything else keeps the
        daemon path, which settles the spelling and records the rejection.
        """
        query = self._optional_string(params.get("guard-home", [None])[-1])
        if query is None:
            return True
        try:
            claimed = os.path.normpath(os.path.expanduser(query))
            own = os.path.normpath(str(daemon_server.store.guard_home))  # pyright: ignore[reportAttributeAccessIssue]
        except (AttributeError, TypeError, ValueError):
            return False
        return claimed == own

    def _record_hook_path_rejection(self, *, parameter: str, reason: str) -> None:
        self._record_bounded_denial_event(
            "daemon.hook.path_rejected",
            {
                "method": self.command,
                "path": urlparse(self.path).path,
                "parameter": parameter,
                "reason": reason,
            },
        )

    @staticmethod
    def _hook_workspace_spelling(value: object) -> str | None:
        """The workspace spelling a hook sent, read out of the request as-is.

        What the spelling means -- a sentinel standing for "no workspace", a
        `~` to expand, the shared temporary root a workspaceless process runs
        in -- is the runtime's to settle, under the `hook-workspace` rule.
        """

        return value if isinstance(value, str) else None

    @staticmethod
    def _runtime_hook_exec_command_workdir(payload: dict[str, object]) -> tuple[bool, str | None]:
        """Whether this call named a working directory, and how it spelled it.

        The flag and the spelling are separate answers: a call that carries a
        `workdir` Guard cannot use is rejected, while a call that carries none
        falls through to the workspace the request named elsewhere.
        """

        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or tool_name.strip().casefold() != "exec_command":
            return False, None
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict) or "workdir" not in tool_input:
            return False, None
        value = tool_input.get("workdir")
        return True, value if isinstance(value, str) else None

    def _settled_hook_directories(
        self,
        *candidates: tuple[str, str | None] | tuple[str, str | None, str],
        deadline_monotonic: float | None = None,
    ) -> _HookDirectories:
        """Ask the native owner about every directory this request named.

        The runtime decides which directories a hook may name; this handler
        only frames the question and reads the answer. A runtime that cannot
        answer refuses the request rather than letting the daemon work the
        verdict out for itself, so an unreachable resident never widens what
        a hook reaches.

        A candidate may carry a third element naming the rule to hold it to,
        which is how one request asks about several spellings of the same
        workspace -- the query string, the payload, the call's own working
        directory -- without their labels colliding.

        A route holding a deadline passes it, so settling paths cannot spend
        a budget the hook still needs for its own answer.
        """

        asked: list[DirectoryTrustCandidate] = [
            (candidate[0], candidate[1], candidate[2]) if len(candidate) == 3 else (candidate[0], candidate[1])
            for candidate in candidates
            if candidate[1] is not None
        ]
        if not asked:
            return _HookDirectories(())
        try:
            daemon_server = self._daemon_server()
            verdicts = native_directory_trust(
                asked,
                guard_home=daemon_server.store.guard_home,
                # The home this daemon was configured with, not whichever home
                # the process happens to be running as: the runtime expands `~`
                # against it and treats it as a trusted root, so letting it
                # fall back to `Path.home()` would settle these paths against a
                # different home than the one the rest of the route uses.
                home_dir=daemon_server.home_dir,
                deadline_monotonic=deadline_monotonic,
            )
        except NativeDirectoryTrustError as error:
            # Nothing was settled, so the request is refused under the first
            # candidate it named -- reported the same way a verdict against
            # that candidate would be, not under the label the spellings are
            # held apart by.
            raise _HookPathValidationError(
                _reported_hook_parameter(asked[0][0]), _DIRECTORY_TRUST_UNAVAILABLE
            ) from error
        return _HookDirectories(verdicts)
