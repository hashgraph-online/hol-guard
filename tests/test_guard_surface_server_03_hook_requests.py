from __future__ import annotations

from tests.test_guard_surface_server import (
    GuardDaemonServer,
    GuardStore,
    daemon_server_module,
    json,
    open_authenticated_claude_request,
    pytest,
    runtime_hook_deadline_module,
    time,
    urllib,
    urlopen_json,
)


class TestGuardSurfaceServer:
    def test_guard_daemon_claude_hook_endpoint_returns_native_pretooluse_response(self, tmp_path) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        store = GuardStore(home_dir)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            hook_request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?"
                    f"home={urllib.parse.quote(str(home_dir))}&workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Read",
                        "tool_input": {"file_path": str(workspace_dir / ".env")},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with open_authenticated_claude_request(daemon, hook_request, timeout=5) as response:
                hook_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert hook_payload["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert hook_payload["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert (
            "HOL Guard intercepted Claude's attempt to use Read for local .env file to protect your local secrets."
            in json.dumps(hook_payload)
        )
        assert "protect your local secrets" in hook_payload["hookSpecificOutput"]["permissionDecisionReason"].lower()
        assert store.list_guard_sessions() == []

    def test_guard_daemon_pi_hook_endpoint_returns_blocked_runtime_review_payload(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(daemon_server_module, "_RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS", 10.0)
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        store = GuardStore(home_dir)
        monkeypatch.setattr(daemon_server_module, "_RUNTIME_HOOK_ADMISSION_TIMEOUT_SECONDS", 10.0)
        monkeypatch.setattr(daemon_server_module, "_RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS", 8.0)
        monkeypatch.setattr(runtime_hook_deadline_module, "_MAX_BUDGET_SECONDS", 12.0)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        monkeypatch.setattr(daemon._server.hook_process_runner, "_timeout_seconds", 8.0)
        daemon.start()
        try:
            assert daemon._server.hook_process_runner.wait_for_capacity(  # pyright: ignore[reportPrivateUsage]
                minimum_workers=1, timeout_seconds=15
            )
            health_deadline = time.monotonic() + 5
            while True:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=1) as health:
                        assert json.loads(health.read().decode("utf-8"))["ok"] is True
                    break
                except OSError:
                    if time.monotonic() >= health_deadline:
                        raise
                    time.sleep(0.05)
            hook_request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(home_dir))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": "kubectl get secret prod -o yaml"},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            hook_deadline = time.monotonic() + 5
            last_post_error: BaseException | None = None
            while True:
                try:
                    hook_payload = urlopen_json(hook_request, timeout=15, attempts=1)
                    break
                except ConnectionRefusedError as exc:
                    last_post_error = exc
                except urllib.error.URLError as exc:
                    if not isinstance(exc.reason, ConnectionRefusedError):
                        raise
                    last_post_error = exc
                if time.monotonic() >= hook_deadline:
                    assert last_post_error is not None
                    raise last_post_error
                time.sleep(0.05)
            if str(hook_payload.get("reason", "")).startswith(
                "HOL Guard blocked this action because isolated local review could not complete safely."
            ):
                assert daemon._server.hook_process_runner.wait_for_capacity(  # pyright: ignore[reportPrivateUsage]
                    minimum_workers=1, timeout_seconds=15
                )
                hook_payload = urlopen_json(hook_request, timeout=15)
        finally:
            daemon.stop()

        assert hook_payload["decision"] == "deny"
        assert "Kubernetes secret read command" in str(hook_payload["reason"]), {
            "hook_payload": hook_payload,
            "worker_stats": daemon._server.hook_process_runner.stats(),
        }

    def test_guard_daemon_cursor_hook_endpoint_applies_hook_env_overlay(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
        monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "0")
        store = GuardStore(tmp_path / "guard-home")
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        captured: dict[str, str | None] = {}

        def fake_review(**kwargs):
            hook_env = kwargs["hook_env"]
            captured["binding"] = hook_env.get("HOL_GUARD_CURSOR_APPROVAL_BINDING")
            captured["proof"] = hook_env.get("HOL_GUARD_CURSOR_AFTER_SHELL_PROOF")
            captured["managed"] = hook_env.get("HOL_GUARD_MANAGED_CURSOR_HOOK")
            captured["session"] = hook_env.get("CURSOR_SESSION_ID")
            from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessReview

            return HookProcessReview({}, None)

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        monkeypatch.setattr(daemon._server.hook_process_runner, "review", fake_review)

        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/cursor?"
                    f"guard-home={urllib.parse.quote(str(store.guard_home))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(
                    {
                        "hook_event_name": "afterShellExecution",
                        "tool_name": "Bash",
                        "tool_input": {"command": "echo hi"},
                        "hook_env": {
                            "HOL_GUARD_MANAGED_CURSOR_HOOK": "1",
                            "HOL_GUARD_CURSOR_APPROVAL_BINDING": "binding-123",
                            "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF": "proof-456",
                            "CURSOR_SESSION_ID": "cursor-session-789",
                            "PATH": "/should/not/be/forwarded",
                        },
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert response.status == 200
        assert payload == {}
        assert captured == {
            "binding": "binding-123",
            "proof": "proof-456",
            "managed": "1",
            "session": "cursor-session-789",
        }

    def test_guard_daemon_claude_hook_endpoint_requires_auth_and_records_audit(self, tmp_path, monkeypatch) -> None:
        # This tests audit contents, not the production write deadline. Coverage
        # tracing can keep a background SQLite writer busy beyond that deadline.
        monkeypatch.setattr(daemon_server_module, "_AUTH_AUDIT_SQLITE_TIMEOUT_SECONDS", 5.0)
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        store = GuardStore(home_dir)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?"
                    f"home={urllib.parse.quote(str(home_dir))}&workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=15)
        finally:
            daemon.stop()

        assert error.value.code == 401
        payload = json.loads(error.value.read().decode("utf-8"))
        assert payload["error"] == "unauthorized"
        # The handler commits the audit synchronously before writing the 401.
        events = store.list_events(event_name="daemon.auth.unauthorized")
        assert events, "unauthorized audit event was never persisted"
        assert events[-1]["payload"]["path"] == "/v1/hooks/claude-code"

    def test_guard_daemon_claude_hook_endpoint_returns_notification_context_with_auth(self, tmp_path) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        store = GuardStore(home_dir)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            pretool_request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?"
                    f"home={urllib.parse.quote(str(home_dir))}&workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(
                    {
                        "session_id": "session-http-hook-1",
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Read",
                        "tool_input": {"file_path": str(workspace_dir / ".env")},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with open_authenticated_claude_request(daemon, pretool_request, timeout=5):
                pass

            notification_request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?"
                    f"home={urllib.parse.quote(str(home_dir))}&workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(
                    {
                        "session_id": "session-http-hook-1",
                        "hook_event_name": "Notification",
                        "notification_type": "permission_prompt",
                        "tool_name": "Read",
                        "message": "Claude needs your permission to use Read",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with open_authenticated_claude_request(daemon, notification_request, timeout=5) as response:
                notification_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert notification_payload["hookSpecificOutput"]["hookEventName"] == "Notification"
        assert (
            "HOL Guard intercepted Claude's attempt to use Read and is routing it to a HOL Guard approval question."
            in (notification_payload["systemMessage"])
        )
        assert (
            "HOL Guard needs the user's explicit decision before Read can run"
            in (notification_payload["hookSpecificOutput"]["additionalContext"])
        )
        assert "AskUserQuestion" in notification_payload["hookSpecificOutput"]["additionalContext"]
        assert "Keep blocked" in notification_payload["hookSpecificOutput"]["additionalContext"]

    def test_guard_daemon_claude_hook_endpoint_rejects_relative_workspace_path_and_records_audit(
        self, tmp_path
    ) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                (f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?workspace=relative-workspace"),
                data=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as error:
                open_authenticated_claude_request(daemon, request, timeout=5)
        finally:
            daemon.stop()

        assert error.value.code == 400
        payload = json.loads(error.value.read().decode("utf-8"))
        assert payload["error"] == "invalid_hook_workspace_path"
        events = store.list_events(event_name="daemon.hook.path_rejected")
        assert events[-1]["payload"]["parameter"] == "workspace"
        assert events[-1]["payload"]["reason"] == "relative_path"
