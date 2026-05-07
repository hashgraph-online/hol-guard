"""Tests for ApprovalCenterLocator and ensure_approval_center helpers (T676-T683, T688-T694)."""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from unittest.mock import patch

import pytest

manager_mod = pytest.importorskip(
    "codex_plugin_scanner.guard.daemon.manager",
    reason="Guard daemon manager not importable",
)

ApprovalCenterLocator = manager_mod.ApprovalCenterLocator
write_approval_center_locator = manager_mod.write_approval_center_locator
read_approval_center_locator = manager_mod.read_approval_center_locator
ensure_approval_center = manager_mod.ensure_approval_center


class TestApprovalCenterLocator:
    def _make_locator(self, guard_home: Path, pid: int = os.getpid()) -> ApprovalCenterLocator:
        return ApprovalCenterLocator(
            guard_home=guard_home,
            daemon_url="http://127.0.0.1:6174",
            approval_url_base="http://127.0.0.1:6174",
            pid=pid,
            started_at="2026-01-01T00:00:00Z",
            state_path=guard_home / "daemon-state.json",
        )

    def test_locator_is_dataclass(self) -> None:
        import dataclasses as dc

        assert dc.is_dataclass(ApprovalCenterLocator)

    def test_write_and_read_roundtrip(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard"
        guard_home.mkdir()
        locator = self._make_locator(guard_home)
        write_approval_center_locator(guard_home, locator)
        result = read_approval_center_locator(guard_home)
        assert result is not None
        assert result.daemon_url == "http://127.0.0.1:6174"
        assert result.pid == os.getpid()
        assert result.guard_home == guard_home

    def test_read_missing_returns_none(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard"
        guard_home.mkdir()
        assert read_approval_center_locator(guard_home) is None

    def test_read_malformed_json_returns_none(self, tmp_path: Path) -> None:
        guard_home = tmp_path / "guard"
        guard_home.mkdir()
        (guard_home / "approval-center-locator.json").write_text("not json", encoding="utf-8")
        assert read_approval_center_locator(guard_home) is None

    def test_stale_locator_dead_pid_ignored(self, tmp_path: Path) -> None:
        """T679: Stale locator with a dead PID must be silently ignored."""
        guard_home = tmp_path / "guard"
        guard_home.mkdir()
        dead_pid = 999999999
        locator = ApprovalCenterLocator(
            guard_home=guard_home,
            daemon_url="http://127.0.0.1:6174",
            approval_url_base="http://127.0.0.1:6174",
            pid=dead_pid,
            started_at="2026-01-01T00:00:00Z",
            state_path=guard_home / "daemon-state.json",
        )
        write_approval_center_locator(guard_home, locator)
        result = read_approval_center_locator(guard_home)
        assert result is None, "Dead PID locator must be ignored"

    def test_moved_daemon_port_updates_locator(self, tmp_path: Path) -> None:
        """T680: Writing a new locator with a different port replaces the old one."""
        guard_home = tmp_path / "guard"
        guard_home.mkdir()
        original = self._make_locator(guard_home)
        write_approval_center_locator(guard_home, original)

        updated = dataclasses.replace(
            original,
            daemon_url="http://127.0.0.1:7777",
            approval_url_base="http://127.0.0.1:7777",
        )
        write_approval_center_locator(guard_home, updated)
        result = read_approval_center_locator(guard_home)
        assert result is not None
        assert result.daemon_url == "http://127.0.0.1:7777"


class TestEnsureApprovalCenter:
    def test_starts_daemon_when_no_locator(self, tmp_path: Path) -> None:
        """T682: ensure_approval_center starts daemon when no locator exists."""
        guard_home = tmp_path / "guard"
        guard_home.mkdir()
        with patch.object(manager_mod, "ensure_guard_daemon", return_value="http://127.0.0.1:6174") as mock_start:
            result = ensure_approval_center(guard_home)
        mock_start.assert_called_once_with(guard_home)
        assert result.daemon_url == "http://127.0.0.1:6174"
        assert result.guard_home == guard_home

    def test_reuses_healthy_daemon(self, tmp_path: Path) -> None:
        """T683: ensure_approval_center reuses healthy (alive PID) daemon without restarting."""
        guard_home = tmp_path / "guard"
        guard_home.mkdir()
        alive_pid = os.getpid()
        locator = ApprovalCenterLocator(
            guard_home=guard_home,
            daemon_url="http://127.0.0.1:6174",
            approval_url_base="http://127.0.0.1:6174",
            pid=alive_pid,
            started_at="2026-01-01T00:00:00Z",
            state_path=guard_home / "daemon-state.json",
        )
        write_approval_center_locator(guard_home, locator)
        with patch.object(manager_mod, "ensure_guard_daemon") as mock_start:
            result = ensure_approval_center(guard_home)
        mock_start.assert_not_called()
        assert result.daemon_url == "http://127.0.0.1:6174"


class TestFallbackCliCommand:
    def test_guard_approval_request_has_fallback_cli_command_field(self) -> None:
        """T688: GuardApprovalRequest must have fallback_cli_command field."""
        from codex_plugin_scanner.guard.models import GuardApprovalRequest

        request = GuardApprovalRequest(
            request_id="req-001",
            harness="codex",
            artifact_id="art-001",
            artifact_name="test",
            artifact_hash="abc123",
            policy_action="block",
            recommended_scope="exact",
            changed_fields=(),
            source_scope="local",
            config_path="/tmp/config",
            review_command="hol-guard doctor",
            approval_url="http://127.0.0.1:6174/#/approve/req-001",
            fallback_cli_command="hol-guard approvals approve req-001",
        )
        assert request.fallback_cli_command == "hol-guard approvals approve req-001"

    def test_fallback_cli_command_defaults_to_none(self) -> None:
        """T688: fallback_cli_command must default to None for backwards compatibility."""
        from codex_plugin_scanner.guard.models import GuardApprovalRequest

        request = GuardApprovalRequest(
            request_id="req-002",
            harness="codex",
            artifact_id="art-002",
            artifact_name="test",
            artifact_hash="abc123",
            policy_action="block",
            recommended_scope="exact",
            changed_fields=(),
            source_scope="local",
            config_path="/tmp/config",
            review_command="hol-guard doctor",
            approval_url="http://127.0.0.1:6174/#/approve/req-002",
        )
        assert request.fallback_cli_command is None

    def test_fallback_cli_command_appears_in_to_dict(self) -> None:
        """T688: fallback_cli_command must be in the serialized dict."""
        from codex_plugin_scanner.guard.models import GuardApprovalRequest

        cmd = "hol-guard approvals approve req-003"
        request = GuardApprovalRequest(
            request_id="req-003",
            harness="codex",
            artifact_id="art-003",
            artifact_name="test",
            artifact_hash="abc123",
            policy_action="block",
            recommended_scope="exact",
            changed_fields=(),
            source_scope="local",
            config_path="/tmp/config",
            review_command="hol-guard doctor",
            approval_url="http://127.0.0.1:6174/#/approve/req-003",
            fallback_cli_command=cmd,
        )
        as_dict = request.to_dict()
        assert as_dict["fallback_cli_command"] == cmd
