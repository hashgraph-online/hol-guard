"""Dashboard updates and legacy route responses."""

from __future__ import annotations

from . import server as _server


def _handle_dashboard_update(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    force_pypi_reinstall = bool(payload.get("force_pypi_reinstall"))
    guard_home = self.server.store.guard_home  # type: ignore[attr-defined]
    status_payload = _server.build_guard_update_status_payload(guard_home=guard_home)
    if status_payload.get("python_update_required") is True:
        self._write_json(
            {
                "error": "update_not_supported",
                "message": status_payload.get("blocked_reason") or "Update requires a different Python runtime.",
            },
            status=400,
        )
        return
    recovery_reinstall_available = bool(status_payload.get("recovery_reinstall_available"))
    if force_pypi_reinstall and not recovery_reinstall_available:
        self._write_json(
            {
                "error": "update_not_supported",
                "message": status_payload.get("blocked_reason") or "Reinstall is not available for this install.",
            },
            status=400,
        )
        return
    if status_payload.get("auto_updatable") is not True and not force_pypi_reinstall:
        self._write_json(
            {
                "error": "update_not_supported",
                "message": status_payload.get("blocked_reason") or "Automatic update is not available.",
            },
            status=400,
        )
        return
    if status_payload.get("update_available") is not True and not force_pypi_reinstall:
        self._write_json(
            {
                "error": "update_not_available",
                "message": "Guard is already on the latest version.",
            },
            status=400,
        )
        return
    self._write_json(
        _server.schedule_guard_dashboard_update(
            guard_home,
            daemon_pid=_server.os.getpid(),
            daemon_port=self._daemon_server().daemon_port(),
            force_pypi_reinstall=force_pypi_reinstall,
            include_alpha=status_payload.get("release_channel") == "alpha",
            status_payload=status_payload,
        )
    )


def _handle_codex_live_decision(
    self: _server._GuardDaemonHandler, request_id: str, payload: _server.Mapping[str, object]
) -> None:
    request = self.server.store.get_approval_request(request_id)  # type: ignore[attr-defined]
    from .codex_native_live_decision import complete_native_codex_live_decision, is_native_codex_review

    if is_native_codex_review(request):
        daemon_server = self._daemon_server()
        result = complete_native_codex_live_decision(
            daemon_server.store,
            worker=daemon_server.hook_worker,
            request_id=request_id,
            payload=payload,
            deadline=_server.time.monotonic() + _server._RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS,
        )
        self._write_json(result, status=200 if result.get("completed") is True else 409)
        return
    previous = self.server.store.get_request_resume(request_id)  # type: ignore[attr-defined]
    claimed_hash, claimed_request_id = _server._codex_live_replay_authority(request, previous)
    if isinstance(request, _server.Mapping) and request.get("resolution_action") == "allow":
        authority = _server.resolve_codex_live_allow_authority(
            self.server.store,  # type: ignore[attr-defined]
            request=request,
            request_id=request_id,
            now=_server._now(),
        )
        artifact_hash = request.get("artifact_hash")
        if authority is not None and isinstance(artifact_hash, str) and artifact_hash:
            claimed_hash = artifact_hash
            claimed_request_id = request_id
    fresh_allow_authorized = self._revalidate_codex_live_allow(
        request,
        payload,
        claimed_saved_allow_hash=claimed_hash,
        claimed_approval_request_id=claimed_request_id,
    )
    result = _server.complete_codex_live_decision(
        self.server.store,  # type: ignore[attr-defined]
        request_id=request_id,
        now=_server._now(),
        fresh_allow_authorized=fresh_allow_authorized,
        config_reader=self._daemon_server().hook_config_reader,
    )
    self._write_json(result, status=200 if result.get("completed") is True else 409)


def _revalidate_codex_live_allow(
    self: _server._GuardDaemonHandler,
    request: object,
    payload: _server.Mapping[str, object],
    *,
    claimed_saved_allow_hash: str | None = None,
    claimed_approval_request_id: str | None = None,
) -> bool:
    daemon_server = self._daemon_server()
    home_dir = daemon_server.home_dir
    return _server.revalidate_codex_live_allow(
        request,
        payload,
        home_dir=home_dir,
        claimed_saved_allow_hash=claimed_saved_allow_hash,
        claimed_approval_request_id=claimed_approval_request_id,
        reviewer=lambda hook_payload, workspace, claimed_hash, claimed_request_id: (
            daemon_server.hook_process_runner.review(
                payload=hook_payload,
                harness="codex",
                home_dir=home_dir,
                guard_home=daemon_server.store.guard_home,
                workspace=workspace,
                hook_env={},
                deadline=_server.time.monotonic() + _server._RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS,
                claim_saved_approval=False,
                claimed_saved_allow_hash=claimed_hash,
                claimed_trusted_request_override=claimed_hash is not None,
                claimed_approval_request_id=claimed_request_id,
            ).payload
        ),
    )


def _handle_cloud_review_settings(self: _server._GuardDaemonHandler, payload: dict[str, object]) -> None:
    from .cloud_review_settings_route import handle_cloud_review_settings

    lifecycle = self.server.command_queue_lifecycle  # type: ignore[attr-defined]
    handle_cloud_review_settings(
        self.server.store,
        payload,
        refresh_workers=lifecycle.refresh_command_queue_worker if lifecycle is not None else None,
        write_json=self._write_json,
        write_approval_gate_error=self._write_approval_gate_error,
    )


def _handle_command_queue_worker_refresh(self: _server._GuardDaemonHandler) -> None:
    lifecycle = self.server.command_queue_lifecycle  # type: ignore[attr-defined]
    if lifecycle is None:
        self._write_json({"error": "command_queue_lifecycle_unavailable"}, status=503)
        return
    self._write_json(
        lifecycle.refresh_command_queue_worker(),
        extra_headers={"Cache-Control": "no-store"},
    )


def _write_legacy_pairing_disabled(self: _server._GuardDaemonHandler) -> None:
    self._write_json(
        {
            "error": "legacy_pairing_disabled",
            "message": "Use hol-guard connect for browser OAuth.",
        },
        status=410,
    )


def _write_legacy_cloud_handoff_disabled(self: _server._GuardDaemonHandler) -> None:
    self._write_json(
        {
            "error": "legacy_cloud_handoff_disabled",
            "message": "Use hol-guard connect for browser OAuth.",
        },
        status=410,
    )
