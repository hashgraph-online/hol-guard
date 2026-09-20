from __future__ import annotations

from tests.test_guard_surface_server import (
    GuardDaemonServer,
    GuardStore,
    daemon_server_module,
    json,
    os,
    pytest,
    sys,
    tempfile,
    time,
    urllib,
)


class TestGuardSurfaceServer:
    def test_guard_daemon_pi_hook_endpoint_accepts_owned_temporary_workspace(self, tmp_path, monkeypatch) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        home_dir.mkdir()
        workspace_dir.mkdir()
        store = GuardStore(tmp_path / "guard-home")
        monkeypatch.setattr(
            daemon_server_module._GuardDaemonHandler,
            "_hook_safe_roots",
            lambda _self: (home_dir.resolve(),),
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessReview

        captured: dict[str, object] = {}

        def review(**kwargs: object) -> HookProcessReview:
            captured["workspace"] = kwargs["workspace"]
            return HookProcessReview({"decision": "allow"}, None)

        monkeypatch.setattr(
            daemon._server.hook_process_runner,
            "review",
            review,
        )
        daemon.start()

        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(store.guard_home))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "read",
                        "tool_input": {"path": "README.md"},
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
        assert payload == {"decision": "allow"}
        assert captured["workspace"] == workspace_dir

    @pytest.mark.skipif(os.name != "posix", reason="POSIX shared temp root contract")
    def test_guard_daemon_pi_hook_endpoint_omits_shared_temporary_root_workspace(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        store = GuardStore(tmp_path / "guard-home")
        monkeypatch.setattr(
            daemon_server_module._GuardDaemonHandler,
            "_hook_safe_roots",
            lambda _self: (home_dir.resolve(),),
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessReview

        captured: dict[str, object] = {}

        def review(**kwargs: object) -> HookProcessReview:
            captured["workspace"] = kwargs["workspace"]
            return HookProcessReview({"decision": "allow"}, None)

        monkeypatch.setattr(
            daemon._server.hook_process_runner,
            "review",
            review,
        )
        daemon.start()

        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(store.guard_home))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    "workspace=/tmp"
                ),
                data=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "read",
                        "tool_input": {"path": "README.md"},
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
        assert payload == {"decision": "allow"}
        assert captured["workspace"] is None

    def test_guard_daemon_pi_hook_endpoint_rejects_worker_payload_after_deadline(self, tmp_path, monkeypatch) -> None:
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        home_dir.mkdir()
        workspace_dir.mkdir()
        store = GuardStore(tmp_path / "guard-home")
        monkeypatch.setattr(
            daemon_server_module._GuardDaemonHandler,
            "_hook_safe_roots",
            lambda _self: (home_dir.resolve(),),
        )
        monkeypatch.setattr(daemon_server_module, "_RUNTIME_HOOK_PROCESS_TIMEOUT_SECONDS", 0.03)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessReview

        def late_review(**_kwargs: object) -> HookProcessReview:
            time.sleep(0.05)
            return HookProcessReview({"decision": "allow"}, None)

        monkeypatch.setattr(daemon._server.hook_process_runner, "review", late_review)
        daemon.start()

        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(store.guard_home))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": "curl https://example.test"},
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
        assert payload["decision"] == "allow"
        assert payload["reason_code"] == "daemon_hook_deadline_exhausted"

    def test_guard_daemon_pi_hook_endpoint_rejects_missing_temporary_workspace(self, tmp_path, monkeypatch) -> None:
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        workspace_dir = tmp_path / "missing-workspace"
        store = GuardStore(tmp_path / "guard-home")
        monkeypatch.setattr(
            daemon_server_module._GuardDaemonHandler,
            "_hook_safe_roots",
            lambda _self: (home_dir.resolve(),),
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(store.guard_home))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "read",
                        "tool_input": {"path": "README.md"},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request, timeout=5)
        finally:
            daemon.stop()

        assert error.value.code == 400
        payload = json.loads(error.value.read().decode("utf-8"))
        assert payload["error"] == "invalid_hook_workspace_path"

    @pytest.mark.skipif(os.name != "posix", reason="POSIX /tmp ownership contract")
    def test_guard_daemon_accepts_owned_posix_tmp_workspace(self) -> None:
        handler = object.__new__(daemon_server_module._GuardDaemonHandler)

        with daemon_server_module.tempfile.TemporaryDirectory(
            prefix="hol-guard-owned-workspace-",
            dir="/tmp",
        ) as workspace:
            resolved_workspace = os.path.realpath(workspace)
            assert resolved_workspace.startswith(f"{os.path.realpath('/tmp')}{os.sep}")
            assert handler._is_owned_temporary_hook_workspace(resolved_workspace)

    def test_guard_daemon_accepts_acl_scoped_primary_temp_without_getuid(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        handler = object.__new__(daemon_server_module._GuardDaemonHandler)
        monkeypatch.delattr(daemon_server_module.os, "getuid", raising=False)
        current_home = tmp_path / "home"
        user_temp = current_home / "temp"
        workspace = user_temp / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(daemon_server_module.Path, "home", lambda: current_home)
        monkeypatch.setattr(daemon_server_module.tempfile, "gettempdir", lambda: str(user_temp))

        assert handler._is_owned_temporary_hook_workspace(str(workspace))
        monkeypatch.setattr(daemon_server_module.tempfile, "gettempdir", lambda: str(tmp_path))
        assert not handler._is_owned_temporary_hook_workspace(str(tmp_path))

    @pytest.mark.skipif(sys.platform != "darwin", reason="Darwin user temp root contract")
    def test_guard_daemon_accepts_darwin_workspace_after_sanitized_restart(
        self,
        monkeypatch,
    ) -> None:
        handler = object.__new__(daemon_server_module._GuardDaemonHandler)
        with daemon_server_module.tempfile.TemporaryDirectory(prefix="hol-guard-owned-workspace-") as workspace:
            monkeypatch.setattr(tempfile, "gettempdir", lambda: "/tmp")

            assert handler._is_owned_temporary_hook_workspace(os.path.realpath(workspace))
