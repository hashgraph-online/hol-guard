"""Native hook execution and compatibility transport."""

from __future__ import annotations

from . import server as _server


def _execute_runtime_hook(
    self: _server._GuardDaemonHandler,
    payload: dict[str, object],
    params: _server.Mapping[str, list[str]],
    *,
    hook_env: dict[str, str],
    default_harness: str,
    home_dir: str | None,
    guard_home: str | None,
    workspace: str | None,
    payload_hydrated: bool = False,
    deadline: float | None = None,
) -> None:
    if (
        self._hook_fast_path_enabled()
        or _server._native_mode_requires_rust()
        or not _server.python_oracle_surface_enabled()
    ):
        result = self._handle_runtime_hook_fast(
            payload,
            params,
            default_harness=default_harness,
            home_dir=home_dir,
            guard_home=guard_home,
            workspace=workspace,
            deadline=deadline,
        )
        if result is not None:
            if deadline is not None and _server.time.monotonic() >= deadline:
                result = self._runtime_hook_fail_safe_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason="HOL Guard could not complete local review within the hook deadline. Retry this action.",
                    reason_code="daemon_hook_deadline_exhausted",
                    native_authoritative=_server._native_mode_requires_rust(),
                )
            self._write_json(result)
            return
        if _server._native_mode_requires_rust():
            self._write_json(
                self._runtime_hook_fail_safe_response(
                    payload,
                    params,
                    default_harness=default_harness,
                    reason="HOL Guard could not complete the native hook decision safely.",
                    reason_code="native_hook_worker_unavailable",
                    native_authoritative=True,
                )
            )
            return

    self._handle_runtime_hook_compatibility_cli(
        payload,
        params,
        hook_env=hook_env,
        default_harness=default_harness,
        home_dir=home_dir,
        guard_home=guard_home,
        workspace=workspace,
        deadline=deadline,
    )


def _hook_fast_path_enabled(self: _server._GuardDaemonHandler) -> bool:
    from ..config import hook_fast_path_enabled

    return hook_fast_path_enabled()


def _handle_runtime_hook_fast(
    self: _server._GuardDaemonHandler,
    payload: dict[str, object],
    params: _server.Mapping[str, list[str]],
    *,
    default_harness: str,
    home_dir: str | None,
    guard_home: str | None,
    workspace: str | None,
    deadline: float | None,
) -> dict[str, object] | None:
    """Try the resident hook worker; only explicit rollback may fall back."""
    from .hook_worker import HookWorkerUnsupported

    daemon_server = self._daemon_server()
    effective_home_dir = _server.Path(home_dir) if home_dir is not None else daemon_server.home_dir
    effective_guard_home = _server.Path(guard_home) if guard_home is not None else daemon_server.store.guard_home

    try:
        worker = daemon_server.hook_worker
        return worker.review_http_payload(
            payload=payload,
            params=params,
            default_harness=default_harness,
            home_dir=effective_home_dir,
            guard_home=effective_guard_home,
            workspace=_server.Path(workspace) if workspace else None,
            deadline=deadline,
        )
    except HookWorkerUnsupported:
        if _server._native_mode_requires_rust():
            return self._runtime_hook_fail_safe_response(
                payload,
                params,
                default_harness=default_harness,
                reason="HOL Guard could not complete the native hook decision safely.",
                reason_code="native_hook_worker_unsupported",
                native_authoritative=True,
            )
        if _server.python_oracle_surface_enabled():
            # The test-only oracle may exercise the compatibility seam.
            return None
        return self._runtime_hook_fail_safe_response(
            payload,
            params,
            default_harness=default_harness,
            reason="HOL Guard could not complete the native hook decision safely.",
            reason_code="native_hook_compatibility_disabled",
            native_authoritative=True,
        )
    except Exception as error:
        # Fail safe: deny/block. Do not fall back to compatibility CLI for
        # requests that omitted full output and supplied only guard_source_ref.
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
            native_authoritative=_server._native_mode_requires_rust(),
        )


def _handle_runtime_hook_compatibility_cli(
    self: _server._GuardDaemonHandler,
    payload: dict[str, object],
    params: _server.Mapping[str, list[str]],
    *,
    hook_env: dict[str, str],
    default_harness: str,
    home_dir: str | None,
    guard_home: str | None,
    workspace: str | None,
    deadline: float | None,
) -> None:
    runtime_harness = self._optional_string(params.get("runtime-harness", [None])[-1])
    harness = runtime_harness or default_harness
    daemon_server = self._daemon_server()
    workspace_path = _server.Path(workspace) if workspace is not None else None
    hook_event_name = payload.get("hook_event_name")
    process_timeout_seconds = (
        _server._RUNTIME_POST_HOOK_PROCESS_TIMEOUT_SECONDS
        if isinstance(hook_event_name, str) and hook_event_name.strip().lower() == "posttooluse"
        else _server._RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS
    )
    process_deadline = min(
        deadline if deadline is not None else float("inf"),
        _server.time.monotonic() + process_timeout_seconds,
    )
    admission = daemon_server.runtime_hook_process_scheduler.acquire(
        harness=harness,
        client_key=self._runtime_hook_client_key(payload, workspace),
        lane=self._runtime_hook_lane(payload),
        payload_bytes=0,
        deadline=process_deadline,
    )
    if admission.permit is None:
        self._write_json(
            self._runtime_hook_fail_safe_response(
                payload,
                params,
                default_harness=default_harness,
                reason=(
                    "HOL Guard blocked this action because isolated local review could not complete safely. "
                    "The agent may continue with a different, lower-risk action. "
                    "Retry this exact action after local review recovers."
                ),
                reason_code=admission.reason_code or "daemon_hook_process_not_ready",
            )
        )
        return
    with admission.permit:
        review = daemon_server.hook_process_runner.review(
            payload=payload,
            harness=harness,
            home_dir=_server.Path(home_dir) if home_dir is not None else _server.Path.home(),
            guard_home=(_server.Path(guard_home) if guard_home is not None else daemon_server.store.guard_home),
            workspace=workspace_path,
            hook_env=hook_env,
            deadline=process_deadline,
        )
    scheduler_stats = daemon_server.runtime_hook_process_scheduler.stats()
    daemon_server.hook_process_runner.observe_load(
        queue_p95_ms=scheduler_stats["queue_wait_p95_ms"],
        queued=scheduler_stats["queued"],
    )
    if review.payload is not None and _server.time.monotonic() < process_deadline:
        receipt_accepted = False
        if review.receipt is not None:
            with _server.suppress(Exception):
                receipt_accepted = daemon_server.runtime_hook_evidence_writer.submit_native_decision_receipt(
                    review.receipt
                )
        with _server.suppress(Exception):
            activity_action = review.payload.get("policy_action")
            event = payload.get("hook_event_name", payload.get("hookEventName"))
            if (
                isinstance(event, str)
                and event.replace("_", "").lower() == "pretooluse"
                and _server._native_mode_requires_rust()
                and isinstance(activity_action, str)
            ):
                _ = daemon_server.runtime_hook_evidence_writer.submit_command_activity(
                    harness=harness,
                    event="PreToolUse",
                    payload=payload,
                    succeeded=True,
                    policy_action=activity_action,
                    receipt_id=self._optional_string((review.receipt or {}).get("decision_id"))
                    if receipt_accepted
                    else None,
                    prompted=review.payload.get("prompted") is True,
                    approval_reuse_status=self._optional_string(review.payload.get("approval_reuse_status"))
                    or "not-applicable",
                )
        self._write_json(review.payload)
        return
    reason_code = (
        "daemon_hook_process_deadline_exhausted"
        if review.payload is not None
        else review.reason_code or "daemon_hook_process_failed"
    )
    self._write_json(
        self._runtime_hook_fail_safe_response(
            payload,
            params,
            default_harness=default_harness,
            reason=(
                "HOL Guard blocked this action because isolated local review could not complete safely. "
                "The agent may continue with a different, lower-risk action. "
                "Retry this exact action after local review recovers."
            ),
            reason_code=reason_code,
        )
    )
