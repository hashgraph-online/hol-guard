"""Daemon discovery, authentication recovery and session lifetime."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import client as daemon_client_module
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)


class TestGuardApprovals:
    def test_guard_surface_daemon_client_recovers_missing_auth_token(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"
        cleared: list[Path] = []
        restarted: list[Path] = []
        auth_token_calls = {"count": 0}

        monkeypatch.setattr(
            daemon_client_module,
            "load_guard_daemon_url",
            lambda _guard_home: "http://127.0.0.1:4781",
        )

        def fake_load_auth_token(_guard_home: Path) -> str | None:
            auth_token_calls["count"] += 1
            return "fresh-token" if auth_token_calls["count"] > 1 else None

        monkeypatch.setattr(daemon_client_module, "load_guard_daemon_auth_token", fake_load_auth_token)
        monkeypatch.setattr(
            daemon_client_module,
            "clear_guard_daemon_state",
            lambda path: cleared.append(path),
        )
        monkeypatch.setattr(
            daemon_client_module,
            "ensure_guard_daemon",
            lambda path: restarted.append(path) or "http://127.0.0.1:4781",
        )

        client = daemon_client_module.load_guard_surface_daemon_client(guard_home)

        assert client.daemon_url == "http://127.0.0.1:4781"
        assert client.auth_token == "fresh-token"
        assert cleared == [guard_home]
        assert restarted == [guard_home]

    def test_guard_surface_daemon_client_recovers_missing_daemon_url(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"
        cleared: list[Path] = []
        restarted: list[Path] = []
        daemon_url_calls = {"count": 0}
        auth_token_calls = {"count": 0}

        def fake_load_daemon_url(_guard_home: Path) -> str | None:
            daemon_url_calls["count"] += 1
            return "http://127.0.0.1:4781" if daemon_url_calls["count"] > 1 else None

        def fake_load_auth_token(_guard_home: Path) -> str | None:
            auth_token_calls["count"] += 1
            return "fresh-token" if auth_token_calls["count"] > 1 else None

        monkeypatch.setattr(daemon_client_module, "load_guard_daemon_url", fake_load_daemon_url)
        monkeypatch.setattr(daemon_client_module, "load_guard_daemon_auth_token", fake_load_auth_token)
        monkeypatch.setattr(
            daemon_client_module,
            "clear_guard_daemon_state",
            lambda path: cleared.append(path),
        )
        monkeypatch.setattr(
            daemon_client_module,
            "ensure_guard_daemon",
            lambda path: restarted.append(path) or "http://127.0.0.1:4781",
        )

        client = daemon_client_module.load_guard_surface_daemon_client(guard_home)

        assert client.daemon_url == "http://127.0.0.1:4781"
        assert client.auth_token == "fresh-token"
        assert cleared == [guard_home]
        assert restarted == [guard_home]

    def test_ensure_guard_daemon_uses_stable_default_port(self, tmp_path, monkeypatch):
        launched_commands: list[list[str]] = []
        guard_home = tmp_path / "guard-home"
        expected_port = daemon_manager_module._configured_port(guard_home)
        responses = iter([None, None, f"http://127.0.0.1:{expected_port}"])

        class FakeProcess:
            def poll(self):
                return None

        monkeypatch.delenv("GUARD_DAEMON_PORT", raising=False)
        monkeypatch.setattr(
            daemon_manager_module,
            "load_guard_daemon_url",
            lambda _guard_home: next(responses),
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [],
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_reap_stale_ephemeral_guard_daemons",
            lambda *_args, **_kwargs: None,
        )
        monkeypatch.setattr(daemon_manager_module, "_running_ephemeral_guard_daemon_processes", lambda: [])
        monkeypatch.setattr(
            daemon_manager_module,
            "_running_guard_daemon_processes_for_guard_home",
            lambda _guard_home: [],
        )
        monkeypatch.setattr(
            daemon_manager_module.subprocess,
            "Popen",
            lambda command, **_kwargs: launched_commands.append(command) or FakeProcess(),
        )

        url = daemon_manager_module.ensure_guard_daemon(guard_home)

        assert url == f"http://127.0.0.1:{expected_port}"
        assert launched_commands
        assert launched_commands[0][-2:] == ["--port", str(expected_port)]

    def test_load_guard_daemon_url_rejects_stale_runtime_without_connect_state_support(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"

        class FakeResponse:
            status = 200

            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "ok": True,
                        "tables": [
                            "approval_requests",
                            "guard_connect_requests",
                            "sync_state",
                        ],
                    }
                ).encode("utf-8")

        daemon_manager_module.write_guard_daemon_state(
            guard_home,
            5530,
            "token-123",
            pid=12345,
        )
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_pid_matches_command",
            lambda _pid, expected_guard_home=None: True,
        )
        monkeypatch.setattr(
            daemon_manager_module.urllib.request,
            "urlopen",
            lambda request, timeout=1: FakeResponse(),
        )

        assert daemon_manager_module.load_guard_daemon_url(guard_home) is None

    def test_load_guard_daemon_url_accepts_healthy_daemon_for_matching_source_root(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"

        class FakeResponse:
            status = 200

            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "ok": True,
                        "tables": ["guard_connect_states"],
                        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                    }
                ).encode("utf-8")

        daemon_manager_module.write_guard_daemon_state(
            guard_home,
            5530,
            "token-123",
            pid=12345,
        )
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_pid_matches_command",
            lambda _pid, expected_guard_home=None: True,
        )
        monkeypatch.setattr(
            daemon_manager_module.urllib.request,
            "urlopen",
            lambda request, timeout=1: FakeResponse(),
        )

        assert daemon_manager_module.load_guard_daemon_url(guard_home) == "http://127.0.0.1:5530"

    def test_load_guard_daemon_url_rejects_incompatible_daemon_state(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"

        class FakeResponse:
            status = 200

            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "ok": True,
                        "tables": ["guard_connect_states"],
                        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION - 1,
                    }
                ).encode("utf-8")

        monkeypatch.setattr(
            daemon_manager_module,
            "_load_state",
            lambda _guard_home: {
                "port": 5530,
                "auth_token": "token-123",
                "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION - 1,
                "source_root": daemon_manager_module._current_guard_daemon_source_root(),
                "runtime_fingerprint": daemon_manager_module._current_guard_daemon_runtime_fingerprint(),
            },
        )
        monkeypatch.setattr(
            daemon_manager_module.urllib.request,
            "urlopen",
            lambda request, timeout=1: FakeResponse(),
        )

        assert daemon_manager_module.load_guard_daemon_url(guard_home) is None

    def test_load_guard_daemon_url_adopts_same_fingerprint_from_different_source_root(self, tmp_path, monkeypatch):
        guard_home = tmp_path / "guard-home"

        class FakeResponse:
            status = 200

            def __enter__(self) -> FakeResponse:
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "ok": True,
                        "tables": ["guard_connect_states"],
                        "compatibility_version": daemon_manager_module.GUARD_DAEMON_COMPATIBILITY_VERSION,
                    }
                ).encode("utf-8")

        daemon_manager_module.write_guard_daemon_state(
            guard_home,
            5530,
            "token-123",
            pid=12345,
        )
        monkeypatch.setattr(
            daemon_manager_module,
            "_current_guard_daemon_source_root",
            lambda: "/different/install/path",
        )
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_pid_is_running", lambda _pid: True)
        monkeypatch.setattr(
            daemon_manager_module,
            "_guard_daemon_pid_matches_command",
            lambda _pid, expected_guard_home=None: True,
        )
        monkeypatch.setattr(
            daemon_manager_module.urllib.request,
            "urlopen",
            lambda request, timeout=1: FakeResponse(),
        )

        assert daemon_manager_module.load_guard_daemon_url(guard_home) == "http://127.0.0.1:5530"

    def test_guard_daemon_server_reuses_existing_auth_token(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        token_path = store.guard_home / "daemon-auth-token"
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text("persisted-token", encoding="utf-8")
        token_path.chmod(0o600)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)

        try:
            daemon.start()
            assert daemon._server.auth_token == "persisted-token"
            assert token_path.read_text(encoding="utf-8").strip() == "persisted-token"
        finally:
            daemon.stop()

    def test_guard_daemon_updates_runtime_heartbeat_while_serving_requests(self, tmp_path, monkeypatch):
        store = GuardStore(tmp_path / "guard-home")
        heartbeat_values = [
            "2026-04-11T00:00:00+00:00",
            "2026-04-11T00:00:00+00:00",
            "2026-04-11T00:05:00+00:00",
        ]

        def next_heartbeat() -> str:
            if len(heartbeat_values) > 1:
                return heartbeat_values.pop(0)
            return heartbeat_values[0]

        monkeypatch.setattr(daemon_server_module, "_now", next_heartbeat)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=5):
                pass
            deadline = time.monotonic() + 1
            while True:
                runtime_state = store.get_runtime_state()
                if runtime_state is not None and runtime_state["last_heartbeat_at"] == "2026-04-11T00:05:00+00:00":
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.01)
        finally:
            daemon.stop()

        assert runtime_state is not None
        assert runtime_state["last_heartbeat_at"] == "2026-04-11T00:05:00+00:00"

    def test_guard_store_clears_runtime_state_only_for_matching_session(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_runtime_state(
            session_id="session-active",
            daemon_host="127.0.0.1",
            daemon_port=4455,
            started_at="2026-04-11T00:00:00+00:00",
            last_heartbeat_at="2026-04-11T00:00:00+00:00",
        )

        store.clear_runtime_state(session_id="session-stale")
        active_state = store.get_runtime_state()

        assert active_state is not None
        assert active_state["session_id"] == "session-active"

        store.clear_runtime_state(session_id="session-active")

        assert store.get_runtime_state() is None

    def test_guard_store_touches_runtime_state_only_for_matching_session(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.upsert_runtime_state(
            session_id="session-active",
            daemon_host="127.0.0.1",
            daemon_port=4455,
            started_at="2026-04-11T00:00:00+00:00",
            last_heartbeat_at="2026-04-11T00:00:00+00:00",
        )

        store.touch_runtime_state(
            session_id="session-stale",
            last_heartbeat_at="2026-04-11T01:00:00+00:00",
        )
        unchanged_state = store.get_runtime_state()

        assert unchanged_state is not None
        assert unchanged_state["last_heartbeat_at"] == "2026-04-11T00:00:00+00:00"

        store.touch_runtime_state(
            session_id="session-active",
            last_heartbeat_at="2026-04-11T01:00:00+00:00",
        )
        updated_state = store.get_runtime_state()

        assert updated_state is not None
        assert updated_state["last_heartbeat_at"] == "2026-04-11T01:00:00+00:00"
