"""Tests for daemon state registry (L301) and health endpoint enhancements (L306)."""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module


class TestDaemonStateStartedAt:
    """L301: daemon-state.json must include started_at and pid."""

    def test_write_guard_daemon_state_includes_started_at(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "tok")
        state = json.loads(daemon_manager_module._state_path(guard_home).read_text())
        assert "started_at" in state, "daemon-state.json must contain started_at"

    def test_started_at_is_valid_iso8601(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "tok")
        state = json.loads(daemon_manager_module._state_path(guard_home).read_text())
        started_at = state["started_at"]
        parsed = datetime.fromisoformat(started_at)
        assert parsed.tzinfo is not None, "started_at must be timezone-aware"

    def test_started_at_is_recent(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        before = datetime.now(timezone.utc)
        daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "tok")
        after = datetime.now(timezone.utc)
        state = json.loads(daemon_manager_module._state_path(guard_home).read_text())
        started_at = datetime.fromisoformat(state["started_at"])
        assert before <= started_at <= after, "started_at must be written at call time"

    def test_state_still_includes_pid(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        import os

        daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "tok")
        state = json.loads(daemon_manager_module._state_path(guard_home).read_text())
        assert state.get("pid") == os.getpid()

    def test_state_includes_all_registry_fields(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard-home"
        daemon_manager_module.write_guard_daemon_state(guard_home, 4781, "tok")
        state = json.loads(daemon_manager_module._state_path(guard_home).read_text())
        for field in ("pid", "port", "guard_home", "started_at"):
            assert field in state, f"state must contain {field}"


class TestHealthzEndpoint:
    """L306: /healthz must expose pending_approvals and uptime_seconds."""

    def _start_server(self, tmp_path: Path) -> tuple[str, object]:
        from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
        from codex_plugin_scanner.guard.store import GuardStore

        guard_home = tmp_path / "guard-home"
        store = GuardStore(guard_home=guard_home)
        server = GuardDaemonServer(store, host="127.0.0.1", port=0)
        server.start()
        url = f"http://127.0.0.1:{server.port}"
        return url, server

    def _get_healthz(self, url: str) -> dict:
        with urllib.request.urlopen(f"{url}/healthz", timeout=3) as resp:
            return json.loads(resp.read())

    def test_healthz_includes_pending_approvals(self, tmp_path: Path) -> None:
        url, server = self._start_server(tmp_path)
        try:
            payload = self._get_healthz(url)
            assert "pending_approvals" in payload, "/healthz must include pending_approvals"
        finally:
            server.stop()

    def test_healthz_includes_uptime_seconds(self, tmp_path: Path) -> None:
        url, server = self._start_server(tmp_path)
        try:
            payload = self._get_healthz(url)
            assert "uptime_seconds" in payload, "/healthz must include uptime_seconds"
        finally:
            server.stop()

    def test_healthz_uptime_is_non_negative(self, tmp_path: Path) -> None:
        url, server = self._start_server(tmp_path)
        try:
            payload = self._get_healthz(url)
            assert payload["uptime_seconds"] >= 0.0
        finally:
            server.stop()

    def test_healthz_pending_approvals_is_int(self, tmp_path: Path) -> None:
        url, server = self._start_server(tmp_path)
        try:
            payload = self._get_healthz(url)
            assert isinstance(payload["pending_approvals"], int)
        finally:
            server.stop()

    def test_healthz_still_includes_legacy_approvals_field(self, tmp_path: Path) -> None:
        url, server = self._start_server(tmp_path)
        try:
            payload = self._get_healthz(url)
            assert "approvals" in payload, "legacy approvals field must remain for backward compat"
        finally:
            server.stop()

    def test_healthz_still_includes_version_and_tables(self, tmp_path: Path) -> None:
        url, server = self._start_server(tmp_path)
        try:
            payload = self._get_healthz(url)
            assert "compatibility_version" in payload
            assert "package_version" in payload
            assert "tables" in payload
        finally:
            server.stop()

    def test_healthz_includes_guard_home_for_daemon_identity(self, tmp_path: Path) -> None:
        url, server = self._start_server(tmp_path)
        try:
            payload = self._get_healthz(url)
            assert payload["guard_home"] == str(server.store.guard_home.resolve())
        finally:
            server.stop()
