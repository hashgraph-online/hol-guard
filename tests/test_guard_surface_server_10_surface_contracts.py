from __future__ import annotations

from tests.test_guard_surface_server import (
    GuardArtifact,
    GuardDaemonServer,
    GuardStore,
    GuardSurfaceRuntime,
    _guard_dashboard_session_get_request,
    build_local_dashboard_session_token,
    build_surface_server_contract,
    daemon_server_module,
    datetime,
    json,
    pytest,
    time,
    timezone,
    urllib,
)


class TestGuardSurfaceServer:
    def test_surface_server_contract_is_exposed_during_initialize(self, tmp_path) -> None:
        contract = build_surface_server_contract()
        assert contract["schema_version"] == "guard-surface-server.v1"
        assert contract["protocol"]["current_version"] == "1.1"
        assert contract["protocol"]["minimum_version"] == "1.0"
        assert contract["protocol"]["compatibility"] == "same-major"
        assert "session" in contract["entities"]
        assert "operation" in contract["entities"]
        assert "item" in contract["entities"]
        runtime_snapshot = contract["entities"]["runtime_snapshot"]
        assert "cloud_pairing_state" in runtime_snapshot["required_fields"]
        assert runtime_snapshot["json_schema"]["properties"]["cloud_pairing_state"]["required"] == [
            "state",
            "label",
            "detail",
            "sync_configured",
            "dashboard_url",
            "inbox_url",
            "fleet_url",
            "connect_url",
        ]

        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            initialize_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/initialize",
                data=json.dumps(
                    {
                        "client_name": "approval-center-web",
                        "surface": "approval-center",
                        "supported_protocol_versions": ["1.0", "1.1", "0.9"],
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(initialize_request, timeout=5) as response:
                initialize_payload = json.loads(response.read().decode("utf-8"))

            unsupported_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/initialize",
                data=json.dumps(
                    {
                        "client_name": "approval-center-web",
                        "surface": "approval-center",
                        "supported_protocol_versions": ["2.0"],
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            unsupported_error = None
            try:
                urllib.request.urlopen(unsupported_request, timeout=5)
            except urllib.error.HTTPError as error:
                unsupported_error = error
        finally:
            daemon.stop()

        assert initialize_payload["protocol_version"] == "1.1"
        assert initialize_payload["schema_version"] == "guard-surface-server.v1"
        assert initialize_payload["schema"]["schema_version"] == "guard-surface-server.v1"
        assert initialize_payload["protocol"]["current_version"] == "1.1"
        assert initialize_payload["protocol"]["minimum_version"] == "1.0"
        assert initialize_payload["protocol"]["supported_versions"] == ["1.1", "1.0"]
        assert "auth_token" not in initialize_payload
        assert "dashboard_session_token" not in initialize_payload
        assert "sessions" not in initialize_payload
        assert unsupported_error is not None
        assert unsupported_error.code == 400

    def test_initialize_refreshes_signed_dashboard_session_within_absolute_lifetime(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        original_time = time.time()
        stale_session_token = build_local_dashboard_session_token(
            auth_token=daemon._server.auth_token,
            surface="approval-center",
            expires_in_seconds=1,
        )
        monkeypatch.setattr(daemon_server_module.time, "time", lambda: original_time + 5)

        try:
            initialize_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/initialize",
                data=json.dumps(
                    {
                        "client_name": "guard-dashboard-web",
                        "surface": "dashboard",
                        "supported_protocol_versions": ["1.0", "1.1"],
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Dashboard-Session": stale_session_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(initialize_request, timeout=5) as response:
                initialize_payload = json.loads(response.read().decode("utf-8"))
            refreshed_token = initialize_payload["dashboard_session_token"]
            with urllib.request.urlopen(
                _guard_dashboard_session_get_request(daemon.port, "/v1/settings", refreshed_token),
                timeout=5,
            ) as settings_response:
                settings_payload = json.loads(settings_response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert isinstance(refreshed_token, str)
        assert refreshed_token
        assert refreshed_token != stale_session_token
        assert "auth_token" not in initialize_payload
        assert settings_payload["guard_home"] == str(tmp_path / "guard-home")

    def test_initialize_does_not_refresh_dashboard_session_past_absolute_lifetime(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        original_time = time.time()
        stale_session_token = build_local_dashboard_session_token(
            auth_token=daemon._server.auth_token,
            surface="dashboard",
            expires_in_seconds=1,
            session_started_at=datetime.fromtimestamp(
                original_time - (8 * 24 * 60 * 60),
                tz=timezone.utc,
            ).isoformat(),
        )
        monkeypatch.setattr(daemon_server_module.time, "time", lambda: original_time + 5)

        try:
            initialize_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/initialize",
                data=json.dumps(
                    {
                        "client_name": "guard-dashboard-web",
                        "surface": "dashboard",
                        "supported_protocol_versions": ["1.0", "1.1"],
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Dashboard-Session": stale_session_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(initialize_request, timeout=5) as response:
                initialize_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert "dashboard_session_token" not in initialize_payload
        assert "auth_token" not in initialize_payload

    def test_surface_runtime_persists_sessions_operations_and_items(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        runtime = GuardSurfaceRuntime(store)

        session = runtime.start_session(
            harness="codex",
            surface="cli",
            workspace=str(tmp_path / "workspace"),
            client_name="hol-guard",
            capabilities=("approval-resolution", "receipt-view"),
        )
        operation = runtime.start_operation(
            session_id=str(session["session_id"]),
            operation_type="run",
            harness="codex",
            metadata={"command": "hol-guard run codex"},
        )
        item = runtime.add_item(
            operation_id=str(operation["operation_id"]),
            item_type="approval_requested",
            payload={"artifact_id": "codex:project:workspace_skill", "policy_action": "require-reapproval"},
        )

        sessions = store.list_guard_sessions()
        operations = store.list_guard_operations(session_id=str(session["session_id"]))
        items = store.list_guard_operation_items(str(operation["operation_id"]))

        assert session["status"] == "active"
        assert operation["status"] == "started"
        assert item["item_type"] == "approval_requested"
        assert sessions[0]["session_id"] == session["session_id"]
        assert operations[0]["operation_id"] == operation["operation_id"]
        assert items[0]["payload"]["artifact_id"] == "codex:project:workspace_skill"

    def test_surface_runtime_rejects_unknown_session_for_new_operation(self, tmp_path) -> None:
        runtime = GuardSurfaceRuntime(GuardStore(tmp_path / "guard-home"))

        with pytest.raises(ValueError, match="Unknown guard session"):
            runtime.start_operation(
                session_id="missing-session",
                operation_type="run",
                harness="codex",
            )

    def test_surface_runtime_rejects_unknown_session_for_client_attachment(self, tmp_path) -> None:
        runtime = GuardSurfaceRuntime(GuardStore(tmp_path / "guard-home"))

        with pytest.raises(ValueError, match="Unknown guard session"):
            runtime.attach_client(
                client_id="approval-center-web",
                surface="approval-center",
                session_id="missing-session",
            )

    def test_surface_runtime_rejects_unknown_operation_for_item(self, tmp_path) -> None:
        runtime = GuardSurfaceRuntime(GuardStore(tmp_path / "guard-home"))

        with pytest.raises(ValueError, match="Unknown guard operation"):
            runtime.add_item(
                operation_id="missing-operation",
                item_type="approval_requested",
                payload={"artifact_id": "codex:project:workspace_skill"},
            )

    def test_surface_runtime_rejects_invalid_block_payload_without_persisting_operation(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        runtime = GuardSurfaceRuntime(store)
        session = runtime.start_session(
            harness="codex",
            surface="cli",
            workspace=str(tmp_path / "workspace"),
            client_name="hol-guard",
        )

        with pytest.raises(ValueError, match="invalid_detection_payload"):
            runtime.queue_blocked_operation(
                session_id=str(session["session_id"]),
                operation_type="run",
                harness="codex",
                metadata={"command": "hol-guard run codex"},
                detection={},
                evaluation={"blocked": True},
                approval_center_url="http://127.0.0.1:4455",
                approval_surface_policy="native-or-center",
                open_key=None,
                opener=lambda url: True,
            )

        assert store.list_guard_operations(session_id=str(session["session_id"])) == []

    def test_surface_runtime_opens_new_request_when_mixed_with_reused_request(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        runtime = GuardSurfaceRuntime(store)
        opened_urls: list[str] = []
        session = runtime.start_session(
            harness="pi",
            surface="harness-adapter",
            workspace=str(tmp_path / "workspace"),
            client_name="pi-hook",
        )
        artifact_a = GuardArtifact(
            artifact_id="pi:project:tool-output:a",
            name="Bash credential-looking output",
            harness="pi",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path="~/.pi/agent/settings.json",
            metadata={},
        )
        artifact_b = GuardArtifact(
            artifact_id="pi:project:tool-output:b",
            name="Bash credential-looking output",
            harness="pi",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path="~/.pi/agent/settings.json",
            metadata={},
        )

        def block_payload(*artifacts: GuardArtifact) -> tuple[dict[str, object], dict[str, object]]:
            return (
                {
                    "harness": "pi",
                    "installed": True,
                    "command_available": True,
                    "config_paths": ["~/.pi/agent/settings.json"],
                    "artifacts": [artifact.to_dict() for artifact in artifacts],
                },
                {
                    "artifacts": [
                        {
                            "artifact_id": artifact.artifact_id,
                            "artifact_name": artifact.name,
                            "artifact_hash": f"hash-{artifact.artifact_id[-1]}",
                            "artifact_type": artifact.artifact_type,
                            "source_scope": artifact.source_scope,
                            "config_path": artifact.config_path,
                            "policy_action": "require-reapproval",
                            "changed_fields": ["tool_response"],
                            "launch_target": f"rg deps.config #{artifact.artifact_id[-1]}",
                        }
                        for artifact in artifacts
                    ]
                },
            )

        detection, evaluation = block_payload(artifact_a)
        first = runtime.queue_blocked_operation(
            session_id=str(session["session_id"]),
            operation_type="tool_call",
            harness="pi",
            metadata={"event": "PostToolUse"},
            detection=detection,
            evaluation=evaluation,
            approval_center_url="http://127.0.0.1:5474",
            browser_url="http://127.0.0.1:5474#guard-token=session-token",
            approval_surface_policy="auto-open-once",
            open_key="pi-run",
            opener=lambda url: opened_urls.append(url) or True,
        )
        detection, evaluation = block_payload(artifact_a, artifact_b)
        second = runtime.queue_blocked_operation(
            session_id=str(session["session_id"]),
            operation_type="tool_call",
            harness="pi",
            metadata={"event": "PostToolUse"},
            detection=detection,
            evaluation=evaluation,
            approval_center_url="http://127.0.0.1:5474",
            browser_url="http://127.0.0.1:5474#guard-token=session-token",
            approval_surface_policy="auto-open-once",
            open_key="pi-run",
            opener=lambda url: opened_urls.append(url) or True,
        )

        first_request_id = str(first["approval_requests"][0]["request_id"])
        second_request_id = str(second["approval_requests"][1]["request_id"])
        assert str(second["approval_requests"][0]["request_id"]) == first_request_id
        assert len(opened_urls) == 2
        assert urllib.parse.urlparse(opened_urls[0]).path == f"/requests/{first_request_id}"
        assert urllib.parse.urlparse(opened_urls[1]).path == f"/requests/{second_request_id}"

    def test_surface_runtime_preserves_prompt_request_explanation(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        runtime = GuardSurfaceRuntime(store)
        workspace_dir = tmp_path / "workspace"
        prompt_artifact = GuardArtifact(
            artifact_id="codex:session:prompt-env-read:abc123",
            name="prompt secret read",
            harness="codex",
            artifact_type="prompt_request",
            source_scope="session",
            config_path=str(workspace_dir / ".codex" / "config.toml"),
            metadata={
                "prompt_summary": "Prompt asks the harness to read a local .env file directly.",
                "request_summary": "Codex prompt for `.env`: read .env",
            },
        )
        session = runtime.start_session(
            harness="codex",
            surface="harness-adapter",
            workspace=str(workspace_dir),
            client_name="codex-hook",
        )

        queued = runtime.queue_blocked_operation(
            session_id=str(session["session_id"]),
            operation_type="prompt",
            harness="codex",
            metadata={"event": "UserPromptSubmit"},
            detection={
                "harness": "codex",
                "installed": True,
                "command_available": True,
                "config_paths": [str(workspace_dir / ".codex" / "config.toml")],
                "artifacts": [prompt_artifact.to_dict()],
            },
            evaluation={
                "blocked": True,
                "artifacts": [
                    {
                        "artifact_id": prompt_artifact.artifact_id,
                        "artifact_name": prompt_artifact.name,
                        "artifact_hash": "hash-123",
                        "artifact_type": "prompt_request",
                        "source_scope": "session",
                        "config_path": prompt_artifact.config_path,
                        "policy_action": "require-reapproval",
                        "changed_fields": ["prompt_request"],
                        "launch_target": "Codex prompt for `.env`: read .env",
                        "risk_summary": "Prompt asks the harness to read a local .env file directly.",
                    }
                ],
            },
            approval_center_url="http://127.0.0.1:4455",
            approval_surface_policy="native-or-center",
            open_key=None,
            opener=lambda _url: True,
        )
        request = queued["approval_requests"][0]

        assert request["artifact_type"] == "prompt_request"
        assert request["risk_headline"] == "Prompt asks the harness to read a local .env file directly."
        assert "Codex prompt" in request["launch_summary"]
        assert "active Codex prompt" in request["trigger_summary"]
