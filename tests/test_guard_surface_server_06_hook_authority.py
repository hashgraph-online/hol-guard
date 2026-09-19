from __future__ import annotations

from tests.test_guard_surface_server import (
    GuardDaemonServer,
    GuardStore,
    Path,
    json,
    open_authenticated_claude_request,
    os,
    pytest,
    urllib,
)


class TestGuardSurfaceServer:
    def test_guard_daemon_claude_hook_endpoint_preserves_workspace_none_sentinel(self, tmp_path, monkeypatch) -> None:
        store = GuardStore(tmp_path / "guard-home")
        captured: dict[str, object] = {}

        def fake_review(**kwargs):
            captured["workspace"] = kwargs["workspace"]
            from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessReview

            return HookProcessReview({}, None)

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        monkeypatch.setattr(daemon._server.hook_process_runner, "start", lambda **_: None)
        monkeypatch.setattr(daemon._server.hook_process_runner, "require_initial_capacity", lambda: None)
        daemon.start()
        daemon._server.runtime_hook_process_scheduler.set_active_limit(1)
        monkeypatch.setattr(daemon._server.hook_process_runner, "review", fake_review)
        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?"
                    f"guard-home={urllib.parse.quote(str(store.guard_home))}&workspace=none"
                ),
                data=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with open_authenticated_claude_request(daemon, request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert response.status == 200
        assert payload == {}
        assert captured == {"workspace": None}

    def test_guard_daemon_claude_hook_endpoint_preserves_workspace_trailing_none_sentinel(
        self, tmp_path, monkeypatch
    ) -> None:
        store = GuardStore(tmp_path / "guard-home")
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)
        captured: dict[str, str | None] = {}

        def fake_review(**kwargs):
            captured["workspace"] = str(kwargs["workspace"])
            from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessReview

            return HookProcessReview({}, None)

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()
        monkeypatch.setattr(daemon._server.hook_process_runner, "review", fake_review)

        try:
            trailing_none = workspace_dir / "None"
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?"
                    f"guard-home={urllib.parse.quote(str(store.guard_home))}"
                    f"&workspace={urllib.parse.quote(str(trailing_none))}"
                ),
                data=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with open_authenticated_claude_request(daemon, request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert response.status == 200
        assert payload == {}
        assert captured["workspace"] == str(workspace_dir)

    def test_guard_daemon_claude_hook_endpoint_rejects_workspace_path_outside_safe_roots_and_records_audit(
        self, tmp_path
    ) -> None:
        home_dir = tmp_path / "home"
        linked_workspace = home_dir / "linked-workspace"
        home_dir.mkdir(parents=True, exist_ok=True)
        workspace_target = Path(home_dir.anchor)
        try:
            linked_workspace.symlink_to(workspace_target, target_is_directory=True)
        except (NotImplementedError, OSError):
            pytest.skip("symlinks are not supported in this environment")

        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?"
                    f"home={urllib.parse.quote(str(home_dir))}&workspace={urllib.parse.quote(str(linked_workspace))}"
                ),
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
        assert events[-1]["payload"]["reason"] == "unexpected_root"

    def test_guard_daemon_claude_hook_endpoint_accepts_guard_home_symlink_alias(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        guard_home_alias = tmp_path / "guard-home-alias"
        try:
            guard_home_alias.symlink_to(store.guard_home, target_is_directory=True)
        except (NotImplementedError, OSError):
            pytest.skip("symlinks are not supported in this environment")

        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?"
                    f"guard-home={urllib.parse.quote(str(guard_home_alias))}&workspace=none"
                ),
                data=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "hi"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with open_authenticated_claude_request(daemon, request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert response.status == 200
        assert payload == {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}

    def test_guard_daemon_claude_hook_endpoint_rejects_unexpected_guard_home_and_records_audit(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?"
                    f"guard-home={urllib.parse.quote(str(tmp_path / 'other-guard-home'))}"
                ),
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
        assert payload["error"] == "invalid_hook_guard_home_path"
        events = store.list_events(event_name="daemon.hook.path_rejected")
        assert events[-1]["payload"]["parameter"] == "guard-home"
        assert events[-1]["payload"]["reason"] == "unexpected_guard_home"

    def test_guard_daemon_claude_hook_endpoint_rejects_special_guard_home_path_and_records_audit(
        self, tmp_path
    ) -> None:
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFOs are not supported in this environment")

        fifo_path = tmp_path / "guard-home.fifo"
        os.mkfifo(fifo_path)
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/claude-code?"
                    f"guard-home={urllib.parse.quote(str(fifo_path))}"
                ),
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
        assert payload["error"] == "invalid_hook_guard_home_path"
        events = store.list_events(event_name="daemon.hook.path_rejected")
        assert events[-1]["payload"]["parameter"] == "guard-home"
        assert events[-1]["payload"]["reason"] == "unexpected_guard_home"
