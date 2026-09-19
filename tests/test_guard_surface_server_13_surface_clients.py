from __future__ import annotations

from tests.test_guard_surface_server import (
    GuardDaemonServer,
    GuardStore,
    GuardSurfaceRuntime,
    HarnessContext,
    _approval_center_session_token,
    get_adapter,
    json,
    urllib,
)


class TestGuardSurfaceServer:
    def test_guard_daemon_heartbeat_renews_client_lease(self, tmp_path) -> None:
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
                        "supported_protocol_versions": ["1.0"],
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(initialize_request, timeout=5) as response:
                initialize_payload = json.loads(response.read().decode("utf-8"))
            session_token = _approval_center_session_token(daemon)

            attach_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/clients/attach",
                data=json.dumps(
                    {
                        "client_id": initialize_payload["client_id"],
                        "surface": "approval-center",
                        "lease_seconds": 1,
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Dashboard-Session": session_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(attach_request, timeout=5) as response:
                attach_payload = json.loads(response.read().decode("utf-8"))

            heartbeat_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/clients/heartbeat",
                data=json.dumps(
                    {
                        "client_id": initialize_payload["client_id"],
                        "lease_id": attach_payload["item"]["lease_id"],
                        "lease_seconds": 60,
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Dashboard-Session": session_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(heartbeat_request, timeout=5) as response:
                heartbeat_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        attachments = store.list_guard_client_attachments(surface="approval-center")
        assert heartbeat_payload["renewed"] is True
        assert attachments
        assert attachments[0]["client_id"] == initialize_payload["client_id"]
        assert attachments[0]["lease_id"] == attach_payload["item"]["lease_id"]

    def test_copilot_adapter_implements_surface_runtime_contract(self, tmp_path) -> None:
        adapter = get_adapter("copilot")
        context = HarnessContext(
            home_dir=tmp_path / "home",
            workspace_dir=tmp_path / "workspace",
            guard_home=tmp_path / "guard-home",
        )

        session = adapter.attach_session(
            context,
            session_id="session-123",
            client_name="copilot-cli",
        )
        operation = adapter.start_operation(
            context,
            session_id="session-123",
            operation_type="run",
        )
        approval = adapter.request_approval(
            context,
            request_ids=["req-1", "req-2"],
        )
        resumed = adapter.continue_after_approval(
            context,
            operation_id="operation-123",
            approved=True,
        )

        assert session["session_id"] == "session-123"
        assert operation["operation_type"] == "run"
        assert approval["request_ids"] == ["req-1", "req-2"]
        assert resumed["status"] == "completed"

    def test_guard_surface_runtime_force_open_bypasses_auto_open_once(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        runtime = GuardSurfaceRuntime(store)
        opened_urls: list[str] = []

        first_result = runtime.ensure_surface(
            surface="approval-center",
            approval_center_url="http://127.0.0.1:5474",
            approval_surface_policy="auto-open-once",
            open_key="dashboard",
            opener=lambda url: opened_urls.append(url) or True,
        )
        second_result = runtime.ensure_surface(
            surface="approval-center",
            approval_center_url="http://127.0.0.1:5474",
            approval_surface_policy="auto-open-once",
            open_key="dashboard",
            force_open=True,
            opener=lambda url: opened_urls.append(url) or True,
        )

        assert first_result["opened"] is True
        assert second_result["opened"] is True
        assert opened_urls == ["http://127.0.0.1:5474", "http://127.0.0.1:5474"]

    def test_guard_surface_runtime_force_open_overrides_disabled_policy(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        runtime = GuardSurfaceRuntime(store)
        opened_urls: list[str] = []

        result = runtime.ensure_surface(
            surface="approval-center",
            approval_center_url="http://127.0.0.1:5474",
            approval_surface_policy="never-auto-open",
            open_key="dashboard",
            force_open=True,
            opener=lambda url: opened_urls.append(url) or True,
        )

        assert result["opened"] is True
        assert result["reason"] == "opened"
        assert opened_urls == ["http://127.0.0.1:5474"]
        assert opened_urls == ["http://127.0.0.1:5474"]
