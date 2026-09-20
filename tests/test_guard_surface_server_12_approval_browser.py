from __future__ import annotations

from tests.test_guard_surface_server import (
    GuardConfig,
    GuardDaemonServer,
    GuardStore,
    GuardSurfaceRuntime,
    _browser_url_for_review,
    daemon_server_module,
    guard_commands_module,
    json,
    urllib,
)


class TestGuardSurfaceServer:
    def test_guard_daemon_block_endpoint_queues_approvals_and_applies_auto_open_once(
        self, tmp_path, monkeypatch
    ) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        opened_urls: list[str] = []
        monkeypatch.setattr(daemon_server_module, "open_browser_url", lambda url: opened_urls.append(url) or True)
        daemon.start()

        try:
            initialize_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/initialize",
                data=json.dumps(
                    {
                        "client_name": "hol-guard-cli",
                        "surface": "cli",
                        "supported_protocol_versions": ["1.1", "1.0"],
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(initialize_request, timeout=5) as response:
                response.read()
            auth_token = daemon._server.auth_token

            session_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/sessions/start",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "surface": "cli",
                        "workspace": str(tmp_path / "workspace"),
                        "client_name": "hol-guard",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(session_request, timeout=5) as response:
                session_payload = json.loads(response.read().decode("utf-8"))

            block_payload = {
                "session_id": session_payload["session_id"],
                "operation_type": "run",
                "harness": "codex",
                "metadata": {"command": "hol-guard run codex"},
                "detection": {
                    "harness": "codex",
                    "installed": True,
                    "command_available": True,
                    "config_paths": [str(tmp_path / "workspace" / "codex.json")],
                    "artifacts": [
                        {
                            "artifact_id": "codex:project:workspace_skill",
                            "name": "workspace_skill",
                            "harness": "codex",
                            "artifact_type": "plugin",
                            "source_scope": "project",
                            "config_path": str(tmp_path / "workspace" / "codex.json"),
                            "transport": "stdio",
                        }
                    ],
                },
                "evaluation": {
                    "artifacts": [
                        {
                            "artifact_id": "codex:project:workspace_skill",
                            "artifact_name": "workspace_skill",
                            "artifact_hash": "hash-123",
                            "policy_action": "require-reapproval",
                            "changed_fields": ["command"],
                            "artifact_type": "plugin",
                            "source_scope": "project",
                            "config_path": str(tmp_path / "workspace" / "codex.json"),
                            "launch_target": "python -m workspace_skill",
                        }
                    ]
                },
                "approval_center_url": f"http://127.0.0.1:{daemon.port}",
                "approval_surface_policy": "auto-open-once",
                "open_key": "run-operation",
            }
            first_block_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/operations/block",
                data=json.dumps(block_payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(first_block_request, timeout=5) as response:
                first_block_response = json.loads(response.read().decode("utf-8"))

            second_block_payload = {**block_payload, "open_key": "run-operation-retry"}
            second_block_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/operations/block",
                data=json.dumps(second_block_payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(second_block_request, timeout=5) as response:
                second_block_response = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        first_operation = store.get_guard_operation(str(first_block_response["operation"]["operation_id"]))
        assert first_operation is not None
        first_items = store.list_guard_operation_items(str(first_block_response["operation"]["operation_id"]))
        assert first_block_response["operation"]["status"] == "waiting_on_approval"
        assert len(first_block_response["approval_requests"]) == 1
        assert first_items[0]["item_type"] == "approval_requested"
        first_request_id = first_block_response["approval_requests"][0]["request_id"]
        assert second_block_response["approval_requests"][0]["request_id"] == first_request_id
        assert first_items[0]["payload"]["approval_requests"][0]["request_id"] == first_request_id
        assert first_block_response["surface"]["opened"] is True
        assert second_block_response["surface"]["opened"] is False
        assert second_block_response["surface"]["reason"] == "already-opened"
        opened_url = urllib.parse.urlparse(opened_urls[0])
        opened_fragment = urllib.parse.parse_qs(opened_url.fragment)

        assert len(opened_urls) == 1
        assert (
            f"{opened_url.scheme}://{opened_url.netloc}{opened_url.path}"
            == f"http://127.0.0.1:{daemon.port}/requests/{first_request_id}"
        )
        assert opened_fragment["guard-token"][0].startswith("gld1.")
        assert opened_fragment["guard-token"] != [daemon._server.auth_token]

    def test_browser_url_for_review_preserves_token_for_loopback_host_alias(self) -> None:
        browser_url = "http://127.0.0.1:5474#guard-token=session-token"
        review_url = "http://localhost:5474/requests/req-localhost"

        result = _browser_url_for_review(browser_url, review_url)
        assert result is not None
        parsed = urllib.parse.urlparse(result)
        fragment = urllib.parse.parse_qs(parsed.fragment)

        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "http://localhost:5474/requests/req-localhost"
        assert fragment["guard-token"] == ["session-token"]

    def test_browser_url_for_review_preserves_token_for_bind_host_alias(self) -> None:
        browser_url = "http://0.0.0.0:5474#guard-token=session-token"
        review_url = "http://127.0.0.1:5474/requests/req-bind-host"

        result = _browser_url_for_review(browser_url, review_url)
        assert result is not None
        parsed = urllib.parse.urlparse(result)
        fragment = urllib.parse.parse_qs(parsed.fragment)

        assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == "http://127.0.0.1:5474/requests/req-bind-host"
        assert fragment["guard-token"] == ["session-token"]

    def test_guard_daemon_rejects_legacy_browser_connect_pairing_endpoint(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            initialize_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/initialize",
                data=json.dumps(
                    {
                        "client_name": "hol-guard-cli",
                        "surface": "cli",
                        "supported_protocol_versions": ["1.1"],
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(initialize_request, timeout=5) as response:
                response.read()
            auth_token = daemon._server.auth_token

            legacy_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/connect/requests",
                data=json.dumps(
                    {
                        "sync_url": "https://hol.org/registry/api/v1",
                        "allowed_origin": "https://hol.org",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            error = None
            try:
                urllib.request.urlopen(legacy_request, timeout=5)
            except urllib.error.HTTPError as request_error:
                error = request_error
                payload = json.loads(request_error.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert error is not None
        assert error.code == 410
        assert payload["error"] == "legacy_pairing_disabled"
        assert store.get_cloud_sync_profile() is None

    def test_guard_daemon_allows_private_network_preflight_for_hosted_dashboard(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/capabilities",
                headers={
                    "Access-Control-Request-Headers": "authorization,x-guard-token",
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Private-Network": "true",
                    "Origin": "https://hol.org",
                },
                method="OPTIONS",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                allow_origin = response.headers.get("Access-Control-Allow-Origin")
                allow_private_network = response.headers.get("Access-Control-Allow-Private-Network")
        finally:
            daemon.stop()

        assert response.status == 200
        assert allow_origin == "https://hol.org"
        assert allow_private_network == "true"

    def test_guard_daemon_rejects_legacy_browser_connect_complete_endpoint(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            legacy_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/connect/complete",
                data=urllib.parse.urlencode(
                    {
                        "request_id": "connect-123",
                        "pairing_secret": "pair-secret",
                        "token": "session-token-123",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://evil.example",
                },
                method="POST",
            )

            error = None
            try:
                urllib.request.urlopen(legacy_request, timeout=5)
            except urllib.error.HTTPError as request_error:
                error = request_error
                payload = json.loads(request_error.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert error is not None
        assert error.code == 410
        assert payload["error"] == "legacy_pairing_disabled"
        assert store.get_cloud_sync_profile() is None

    def test_open_approval_center_skips_browser_when_live_surface_is_attached(self, tmp_path, monkeypatch) -> None:
        store = GuardStore(tmp_path / "guard-home")
        runtime = GuardSurfaceRuntime(store)
        config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=None)
        opened_urls: list[str] = []
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.cli.commands_support_hook_payload.open_browser_url",
            lambda url: opened_urls.append(url) or True,
        )

        runtime.attach_client(client_id="approval-center-web", surface="approval-center")

        guard_commands_module._open_approval_center(
            "http://127.0.0.1:4781",
            store=store,
            config=config,
        )

        assert opened_urls == []

    def test_open_approval_center_auto_open_once_tracks_operation_key(self, tmp_path, monkeypatch) -> None:
        store = GuardStore(tmp_path / "guard-home")
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
            approval_surface_policy="auto-open-once",
        )
        opened_urls: list[str] = []
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.cli.commands_support_hook_payload.open_browser_url",
            lambda url: opened_urls.append(url) or True,
        )

        guard_commands_module._open_approval_center(
            "http://127.0.0.1:4781",
            store=store,
            config=config,
            open_key="operation-1",
        )
        guard_commands_module._open_approval_center(
            "http://127.0.0.1:4781",
            store=store,
            config=config,
            open_key="operation-1",
        )
        guard_commands_module._open_approval_center(
            "http://127.0.0.1:4781",
            store=store,
            config=config,
            open_key="operation-2",
        )

        assert opened_urls == ["http://127.0.0.1:4781", "http://127.0.0.1:4781"]

    def test_open_approval_center_honors_notify_only_policy(self, tmp_path, monkeypatch) -> None:
        store = GuardStore(tmp_path / "guard-home")
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
            approval_surface_policy="notify-only",
        )
        opened_urls: list[str] = []
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.cli.commands_support_hook_payload.open_browser_url",
            lambda url: opened_urls.append(url) or True,
        )

        guard_commands_module._open_approval_center(
            "http://127.0.0.1:4781",
            store=store,
            config=config,
        )

        assert opened_urls == []
