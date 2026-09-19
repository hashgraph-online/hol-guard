from __future__ import annotations

from tests.test_guard_surface_server import (
    GuardDaemonServer,
    GuardStore,
    _approval_center_session_token,
    _guard_dashboard_session_get_request,
    json,
    urllib,
)


class TestGuardSurfaceServer:
    def test_guard_daemon_initializes_surface_client_and_tracks_attachments(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            initialize_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/initialize",
                data=json.dumps(
                    {
                        "client_name": "approval-center-web",
                        "client_title": "Guard Approval Center",
                        "version": "1.0.0",
                        "surface": "approval-center",
                        "capabilities": ["notifications", "realtime-stream", "approval-resolution"],
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
        finally:
            daemon.stop()

        assert initialize_payload["protocol_version"] == "1.1"
        assert "auth_token" not in initialize_payload
        assert "approval/list" in initialize_payload["server_capabilities"]["methods"]
        assert attach_payload["attached"] is True
        assert store.list_guard_client_attachments(surface="approval-center")

    def test_guard_daemon_resume_endpoint_tracks_session_attachments_and_operations(self, tmp_path) -> None:
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
                        "supported_protocol_versions": ["1.1", "1.0"],
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(initialize_request, timeout=5) as response:
                initialize_payload = json.loads(response.read().decode("utf-8"))
            session_token = _approval_center_session_token(daemon)

            session_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/sessions/start",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "surface": "approval-center",
                        "workspace": str(tmp_path / "workspace"),
                        "client_name": "approval-center-web",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Dashboard-Session": session_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(session_request, timeout=5) as response:
                session_payload = json.loads(response.read().decode("utf-8"))

            attach_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/clients/attach",
                data=json.dumps(
                    {
                        "client_id": initialize_payload["client_id"],
                        "surface": "approval-center",
                        "session_id": session_payload["session_id"],
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

            with urllib.request.urlopen(
                _guard_dashboard_session_get_request(
                    daemon.port,
                    f"/v1/sessions/{session_payload['session_id']}/resume",
                    session_token,
                ),
                timeout=5,
            ) as response:
                attached_resume_payload = json.loads(response.read().decode("utf-8"))

            operation_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/operations/start",
                data=json.dumps(
                    {
                        "session_id": session_payload["session_id"],
                        "operation_type": "run",
                        "harness": "codex",
                        "metadata": {"command": "hol-guard run codex"},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Dashboard-Session": session_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(operation_request, timeout=5) as response:
                operation_payload = json.loads(response.read().decode("utf-8"))

            with urllib.request.urlopen(
                _guard_dashboard_session_get_request(
                    daemon.port,
                    f"/v1/sessions/{session_payload['session_id']}/resume",
                    session_token,
                ),
                timeout=5,
            ) as response:
                active_resume_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert attach_payload["item"]["session_id"] == session_payload["session_id"]
        assert attached_resume_payload["session"]["status"] == "attached"
        assert attached_resume_payload["attachments"][0]["client_id"] == initialize_payload["client_id"]
        assert attached_resume_payload["operations"] == []
        assert active_resume_payload["session"]["status"] == "active"
        assert active_resume_payload["operations"][0]["operation_id"] == operation_payload["operation_id"]

    def test_guard_daemon_attach_rejects_unknown_session_without_persisting_attachment(self, tmp_path) -> None:
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
                        "supported_protocol_versions": ["1.1"],
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
                        "session_id": "missing-session",
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Dashboard-Session": session_token,
                },
                method="POST",
            )
            attach_error = None
            try:
                urllib.request.urlopen(attach_request, timeout=5)
            except urllib.error.HTTPError as error:
                attach_error = error
        finally:
            daemon.stop()

        assert attach_error is not None
        assert attach_error.code == 400
        assert json.loads(attach_error.read().decode("utf-8")) == {
            "attached": False,
            "error": "Unknown guard session: missing-session",
        }
        assert store.list_guard_client_attachments(surface="approval-center") == []

    def test_guard_daemon_session_and_operation_endpoints_drive_runtime(self, tmp_path) -> None:
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
                        "supported_protocol_versions": ["1.0"],
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
                        "client_title": "HOL Guard CLI",
                        "client_version": "2.0.0",
                        "capabilities": ["approval-resolution", "receipt-view"],
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

            operation_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/operations/start",
                data=json.dumps(
                    {
                        "session_id": session_payload["session_id"],
                        "operation_type": "run",
                        "harness": "codex",
                        "metadata": {"command": "hol-guard run codex"},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(operation_request, timeout=5) as response:
                operation_payload = json.loads(response.read().decode("utf-8"))

            item_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/operations/{operation_payload['operation_id']}/items",
                data=json.dumps(
                    {
                        "item_type": "approval_requested",
                        "payload": {"request_ids": ["req-1", "req-2"]},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(item_request, timeout=5) as response:
                item_payload = json.loads(response.read().decode("utf-8"))

            waiting_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/operations/{operation_payload['operation_id']}/status",
                data=json.dumps(
                    {
                        "status": "waiting_on_approval",
                        "approval_request_ids": ["req-1", "req-2"],
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(waiting_request, timeout=5) as response:
                waiting_payload = json.loads(response.read().decode("utf-8"))

            completed_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/operations/{operation_payload['operation_id']}/status",
                data=json.dumps({"status": "completed"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(completed_request, timeout=5) as response:
                completed_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert session_payload["status"] == "active"
        assert operation_payload["status"] == "started"
        assert item_payload["item"]["item_type"] == "approval_requested"
        assert waiting_payload["operation"]["status"] == "waiting_on_approval"
        assert completed_payload["operation"]["status"] == "completed"
        assert store.get_guard_operation(str(operation_payload["operation_id"]))["status"] == "completed"

    def test_guard_daemon_operation_item_rejects_unknown_operation_with_json_error(self, tmp_path) -> None:
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

            item_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/operations/missing-operation/items",
                data=json.dumps(
                    {
                        "item_type": "approval_requested",
                        "payload": {"request_ids": ["req-1"]},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            item_error = None
            try:
                urllib.request.urlopen(item_request, timeout=5)
            except urllib.error.HTTPError as error:
                item_error = error
        finally:
            daemon.stop()

        assert item_error is not None
        assert item_error.code == 400
        assert json.loads(item_error.read().decode("utf-8")) == {
            "error": "Unknown guard operation: missing-operation",
        }
        assert store.list_guard_operation_items("missing-operation") == []

    def test_guard_daemon_operation_start_rejects_unknown_session_with_json_error(self, tmp_path) -> None:
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

            operation_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/operations/start",
                data=json.dumps(
                    {
                        "session_id": "missing-session",
                        "operation_type": "run",
                        "harness": "codex",
                        "metadata": {"command": "hol-guard run codex"},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            operation_error = None
            try:
                urllib.request.urlopen(operation_request, timeout=5)
            except urllib.error.HTTPError as error:
                operation_error = error
        finally:
            daemon.stop()

        assert operation_error is not None
        assert operation_error.code == 400
        assert json.loads(operation_error.read().decode("utf-8")) == {
            "error": "Unknown guard session: missing-session",
        }
        assert store.list_guard_operations(session_id="missing-session") == []

    def test_guard_daemon_operation_status_rejects_unknown_operation_with_json_error(self, tmp_path) -> None:
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

            status_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/operations/missing-operation/status",
                data=json.dumps({"status": "completed"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            status_error = None
            try:
                urllib.request.urlopen(status_request, timeout=5)
            except urllib.error.HTTPError as error:
                status_error = error
        finally:
            daemon.stop()

        assert status_error is not None
        assert status_error.code == 400
        assert json.loads(status_error.read().decode("utf-8")) == {
            "error": "Unknown guard operation: missing-operation",
        }
