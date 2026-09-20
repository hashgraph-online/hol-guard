"""Runtime hook admission and fail-safe responses."""

from __future__ import annotations

from . import server as _server


def _handle_runtime_hook(
    self: _server._GuardDaemonHandler, payload: dict[str, object], query: str, *, default_harness: str
) -> None:
    from ..runtime.hook_payload_reference import (
        HookPayloadReferenceError,
        hook_payload_reference_size,
    )

    transport_deadline = self._daemon_server().request_deadline(
        self.request,
        _server._RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS,
    )
    params = _server.parse_qs(query)
    remaining_hint = _server._runtime_hook_remaining_hint(payload)
    hinted_deadline = _server.RuntimeHookDeadline.from_remaining_hint(remaining_hint)
    hook_deadline = _server.RuntimeHookDeadline(expires_at=min(hinted_deadline.expires_at, transport_deadline))
    hook_env = _server._runtime_hook_env_overlay_from_payload(payload)
    payload = {key: value for key, value in payload.items() if key != "hook_env"}
    daemon_server = self._daemon_server()
    native_required = _server._native_mode_requires_rust()
    try:
        home_dir = self._validated_hook_directory_string(
            "home",
            self._optional_string(params.get("home", [None])[-1]),
            roots=self._hook_safe_roots(),
        )
        guard_home = self._validated_hook_guard_home(self._optional_string(params.get("guard-home", [None])[-1]))
        workspace_query = self._normalized_hook_workspace_string(params.get("workspace", [None])[-1])
        action_workdir_provided, action_workdir = self._runtime_hook_exec_command_workdir(payload)
        if action_workdir_provided and action_workdir is None:
            raise _server._HookPathValidationError("workspace", "invalid_action_workdir")
        payload_workspace = self._normalized_hook_workspace_string(payload.get("cwd"))
        workspace_candidate = action_workdir or payload_workspace or workspace_query
        workspace = self._validated_hook_directory_string(
            "workspace",
            workspace_candidate,
            roots=self._hook_safe_roots(),
        )
    except _server._HookPathValidationError as error:
        if native_required:
            # The Rust edge still receives the complete raw payload. Use
            # daemon-owned metadata when an optional caller context is
            # missing or invalid; never turn metadata rejection into a
            # Python semantic/source-ref fallback in auto/force.
            self._record_hook_path_rejection(parameter=error.parameter, reason=error.reason)
            home_dir = str(daemon_server.home_dir)
            guard_home = str(daemon_server.store.guard_home)
            workspace = None
        else:
            self._record_hook_path_rejection(parameter=error.parameter, reason=error.reason)
            self._write_json({"error": error.code}, status=400)
            return

    if native_required and not _server.prepare_native_hook_policy(
        self, daemon_server, payload, params, default_harness, workspace, hook_deadline.expires_at
    ):
        return

    runtime_harness = self._optional_string(params.get("runtime-harness", [None])[-1])
    capacity_harness = daemon_server.canonical_hook_capacity_harness(
        (runtime_harness or default_harness).strip().lower().replace("_", "-")
    )
    try:
        referenced_payload_bytes = hook_payload_reference_size(payload)
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
                native_authoritative=native_required,
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
                native_authoritative=native_required,
            )
        )
        return
    with byte_reservation:
        # A referenced payload reserves its bounded maximum, but remains
        # an opaque envelope until the native edge owns its file I/O.
        # Do not hydrate or re-encode it here: duplicate keys in the
        # referenced bytes must not be collapsed by Python before Rust.
        normalized_payload = None
        if referenced_payload_bytes is None:
            normalized_payload = _server.json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        admission = daemon_server.runtime_hook_scheduler.acquire(
            harness=capacity_harness,
            client_key=self._runtime_hook_client_key(payload, workspace),
            lane=self._runtime_hook_lane(payload),
            payload_bytes=payload_bytes,
            deadline=hook_deadline,
            byte_reservation=byte_reservation,
            normalized_payload=normalized_payload,
        )
        if admission.permit is None:
            self._record_hook_capacity_rejection(daemon_server, capacity_harness)
            self._write_json(
                self._runtime_hook_capacity_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason_code=admission.reason_code,
                    native_authoritative=native_required,
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
                hook_env=hook_env,
                default_harness=default_harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
                payload_hydrated=True,
                deadline=hook_deadline.expires_at,
            )
    finally:
        with daemon_server.hook_capacity_lock:
            daemon_server.active_hook_requests -= 1
            daemon_server.hook_harness_active[capacity_harness] -= 1


def _runtime_hook_lane(payload: _server.Mapping[str, object]) -> _server.RuntimeHookLane:
    from .hook_worker import runtime_hook_event_name

    event = runtime_hook_event_name(payload).lower().replace("_", "").replace("-", "")
    if event in {"pretooluse", "permissionrequest", "userpromptsubmit", "userpromptsubmitted"}:
        return "decision"
    return "content-security"


def _runtime_hook_client_key(payload: _server.Mapping[str, object], workspace: str | None) -> str:
    session = next(
        (
            payload.get(key)
            for key in ("session_id", "conversation_id", "thread_id")
            if isinstance(payload.get(key), str) and payload.get(key)
        ),
        "",
    )
    material = f"{workspace or ''}\0{session}"
    return _server.hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:32]


def _runtime_hook_payload_size(payload: _server.Mapping[str, object]) -> int:
    return len(
        _server.json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _record_hook_capacity_rejection(
    daemon_server: _server._GuardDaemonHttpServer,
    capacity_harness: str,
) -> None:
    with daemon_server.hook_capacity_lock:
        daemon_server.rejected_hook_requests += 1
        daemon_server.hook_harness_rejected[capacity_harness] = (
            daemon_server.hook_harness_rejected.get(capacity_harness, 0) + 1
        )


def _runtime_hook_capacity_response(
    self: _server._GuardDaemonHandler,
    payload: _server.Mapping[str, object],
    params: _server.Mapping[str, list[str]],
    *,
    default_harness: str,
    reason_code: _server.RuntimeHookAdmissionReason | None = None,
    native_authoritative: bool = False,
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
        native_authoritative=native_authoritative,
    )


def _runtime_hook_fail_safe_response(
    self: _server._GuardDaemonHandler,
    payload: _server.Mapping[str, object],
    params: _server.Mapping[str, list[str]],
    *,
    default_harness: str,
    reason: str,
    reason_code: str,
    native_authoritative: bool = False,
) -> dict[str, object]:
    runtime_harness = self._optional_string(params.get("runtime-harness", [None])[-1])
    harness = (runtime_harness or default_harness).strip().lower().replace("_", "-")
    event = self._optional_string(payload.get("hook_event_name", payload.get("event"))) or "PreToolUse"
    daemon_server = getattr(self, "server", None)
    workspace_path, home_path = self._validated_fail_safe_hook_paths(params)
    guard_home = (
        None if daemon_server is None else _server.cast(_server._GuardDaemonHttpServer, daemon_server).store.guard_home
    )
    try:
        loaded = (
            None
            if guard_home is None
            else _server.load_guard_config(
                guard_home,
                workspace=workspace_path,
                config_reader=_server.cast(_server._GuardDaemonHttpServer, daemon_server).hook_config_reader,
            )
        )
        observe_mode = loaded is not None and _server.protection_is_off(
            posture=loaded.protection_posture, mode=loaded.mode
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        observe_mode = False
    if observe_mode and not native_authoritative:
        if harness in {"pi", "omp"}:
            return {"decision": "allow", "reason_code": reason_code, "observed_review_failure": True}
        if event == "PermissionRequest":
            return {
                "reason_code": reason_code,
                "hookSpecificOutput": {"hookEventName": event, "decision": {"behavior": "allow"}},
            }
        if event == "PreToolUse":
            return {
                "reason_code": reason_code,
                "hookSpecificOutput": {"hookEventName": event, "permissionDecision": "allow"},
            }
        return {"continue": True, "reason_code": reason_code, "observed_review_failure": True}
    from .hook_availability_policy import availability_harness_response

    payload_dict = dict(payload) if isinstance(payload, _server.Mapping) else {}
    return availability_harness_response(
        payload_dict,
        harness=harness,
        event_name=event,
        reason_code=reason_code,
        reason=reason,
        workspace=workspace_path,
        home_dir=home_path,
        guard_home=guard_home,
        recording_only=observe_mode,
    )


def _validated_fail_safe_hook_paths(
    self: _server._GuardDaemonHandler,
    params: _server.Mapping[str, list[str]],
) -> tuple[_server.Path | None, _server.Path | None]:
    """Return workspace and home directories that passed hook path validation."""

    return (
        self._validated_fail_safe_directory(params, "workspace"),
        self._validated_fail_safe_directory(params, "home"),
    )


def _validated_fail_safe_directory(
    self: _server._GuardDaemonHandler,
    params: _server.Mapping[str, list[str]],
    parameter: str,
) -> _server.Path | None:
    value = self._optional_string(params.get(parameter, [None])[-1])
    if not value:
        return None
    try:
        validated = self._validated_hook_directory_string(
            parameter,
            value,
            roots=self._hook_safe_roots(),
        )
    except _server._HookPathValidationError:
        return None
    return _server.Path(validated) if validated else None
