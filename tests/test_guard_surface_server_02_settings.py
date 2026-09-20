from __future__ import annotations

from tests.test_guard_surface_server import (
    DesktopNotificationSetupResult,
    GuardDaemonServer,
    GuardStore,
    PolicyDecision,
    _guard_get_request,
    daemon_server_module,
    json,
    pytest,
    urllib,
)


class TestGuardSurfaceServer:
    def test_guard_daemon_policy_clear_matches_cli_clear_semantics(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_policy(
            PolicyDecision(harness="codex", scope="harness", action="allow", reason="test"),
            "2026-04-25T00:00:00+00:00",
        )
        store.upsert_policy(
            PolicyDecision(harness="claude-code", scope="harness", action="allow", reason="test"),
            "2026-04-25T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            clear_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/clear",
                data=json.dumps({"harness": "codex"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(clear_request, timeout=5) as response:
                clear_payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert clear_payload["cleared"] == 1
        assert clear_payload["harness"] == "codex"
        remaining = store.list_policy_decisions()
        assert len(remaining) == 1
        assert remaining[0]["harness"] == "claude-code"

    def test_guard_daemon_policy_clear_parses_form_all_strictly(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_policy(
            PolicyDecision(harness="codex", scope="harness", action="allow", reason="test"),
            "2026-04-25T00:00:00+00:00",
        )
        store.upsert_policy(
            PolicyDecision(harness="claude-code", scope="harness", action="deny", reason="test"),
            "2026-04-25T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            false_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/clear",
                data=urllib.parse.urlencode({"all": "false"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(false_request, timeout=5)
            false_payload = json.loads(error.value.read().decode("utf-8"))
            remaining_after_false = store.list_policy_decisions()
            true_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/clear",
                data=urllib.parse.urlencode({"all": "true"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(true_request, timeout=5) as true_response:
                true_payload = json.loads(true_response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert error.value.code == 400
        assert false_payload == {"error": "missing_harness_or_all", "cleared": 0}
        assert len(remaining_after_false) == 2
        assert true_response.status == 200
        assert true_payload["cleared"] == 2
        assert true_payload["harness"] is None
        assert len(store.list_policy_decisions()) == 0

    def test_guard_daemon_settings_can_read_and_update_cli_config(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                _guard_get_request(daemon.port, "/v1/settings", daemon._server.auth_token),
                timeout=5,
            ) as read_response:
                read_payload = json.loads(read_response.read().decode("utf-8"))
            update_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/settings",
                data=json.dumps(
                    {
                        "settings": {
                            "mode": "enforce",
                            "changed_hash_action": "review",
                            "approval_wait_timeout_seconds": 45,
                            "telemetry": True,
                        }
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(update_request, timeout=5) as update_response:
                update_payload = json.loads(update_response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert read_payload["settings"]["mode"] == "prompt"
        assert update_response.status == 200
        assert update_payload["settings"]["mode"] == "enforce"
        assert update_payload["settings"]["changed_hash_action"] == "review"
        assert update_payload["settings"]["approval_wait_timeout_seconds"] == 45
        assert update_payload["settings"]["telemetry"] is True
        config_text = (store.guard_home / "config.toml").read_text(encoding="utf-8")
        assert 'mode = "enforce"' in config_text
        assert 'changed_hash_action = "review"' in config_text
        assert "approval_wait_timeout_seconds = 45" in config_text
        assert "telemetry = true" in config_text

    def test_guard_daemon_notification_setup_endpoint_opens_settings(self, tmp_path, monkeypatch) -> None:
        store = GuardStore(tmp_path / "guard-home")
        calls: list[tuple[str, bool]] = []

        def fake_setup(
            guard_home,
            *,
            approval_url: str,
            force: bool = False,
        ) -> DesktopNotificationSetupResult:
            assert guard_home == store.guard_home
            calls.append((approval_url, force))
            return DesktopNotificationSetupResult(
                platform="Darwin",
                supported=True,
                preview_sent=True,
                settings_opened=True,
                settings_url=(
                    "x-apple.systempreferences:com.apple.Notifications-Settings.extension"
                    "?id=fr.julienxx.oss.terminal-notifier"
                ),
                already_prompted=False,
                notifier_path="/usr/local/bin/terminal-notifier",
            )

        monkeypatch.setattr(daemon_server_module, "ensure_desktop_notification_setup", fake_setup)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            setup_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/notifications/setup",
                data=json.dumps({}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(setup_request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert response.status == 200
        assert calls == [(f"http://127.0.0.1:{daemon.port}/approvals/notification-preview", True)]
        assert payload["supported"] is True
        assert payload["preview_sent"] is True
        assert payload["settings_opened"] is True
        assert "terminal-notifier" in payload["guidance"]

    def test_guard_daemon_notification_setup_endpoint_returns_json_error(self, tmp_path, monkeypatch) -> None:
        store = GuardStore(tmp_path / "guard-home")

        def fail_setup(*_args, **_kwargs) -> DesktopNotificationSetupResult:
            raise OSError("settings unavailable")

        monkeypatch.setattr(daemon_server_module, "ensure_desktop_notification_setup", fail_setup)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            setup_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/notifications/setup",
                data=json.dumps({}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(setup_request, timeout=5)
            payload = json.loads(error.value.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert error.value.code == 500
        assert payload == {"error": "settings unavailable"}

    def test_guard_daemon_settings_accepts_gentle_preset(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            update_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/settings",
                data=json.dumps({"settings": {"security_level": "gentle"}}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(update_request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["settings"]["security_level"] == "gentle"

    def test_guard_daemon_settings_accepts_paranoid_preset(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            update_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/settings",
                data=json.dumps({"settings": {"security_level": "paranoid"}}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(update_request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["settings"]["security_level"] == "paranoid"

    def test_guard_daemon_settings_accepts_new_risk_keys(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            update_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/settings",
                data=json.dumps(
                    {
                        "settings": {
                            "risk_actions": {
                                "prompt_injection": "block",
                                "mcp_dangerous_tool": "block",
                                "guard_bypass": "block",
                                "encoded_exfiltration": "require-reapproval",
                            }
                        }
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(update_request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        risk = payload["settings"].get("risk_actions", {})
        assert risk.get("prompt_injection") == "block"
        assert risk.get("mcp_dangerous_tool") == "block"
        assert risk.get("guard_bypass") == "block"
        assert risk.get("encoded_exfiltration") == "require-reapproval"
