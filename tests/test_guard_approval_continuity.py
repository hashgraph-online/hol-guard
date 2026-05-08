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
        with patch.object(manager_mod, "_guard_daemon_pid_matches_command", return_value=True):
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

    def test_pid_reused_by_non_guard_process_ignored(self, tmp_path: Path) -> None:
        """Regression: PID alive but not a guard daemon → locator must be silently ignored."""
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
        with patch.object(manager_mod, "_guard_daemon_pid_matches_command", return_value=False):
            result = read_approval_center_locator(guard_home)
        assert result is None, "PID reused by non-guard process must be treated as stale"

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
        with patch.object(manager_mod, "_guard_daemon_pid_matches_command", return_value=True):
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
        with (
            patch.object(manager_mod, "_guard_daemon_pid_matches_command", return_value=True),
            patch.object(manager_mod, "_approval_center_daemon_is_healthy", return_value=True),
            patch.object(manager_mod, "ensure_guard_daemon") as mock_start,
        ):
            result = ensure_approval_center(guard_home)
        mock_start.assert_not_called()
        assert result.daemon_url == "http://127.0.0.1:6174"

    def test_wedged_daemon_restarts_when_healthz_fails(self, tmp_path: Path) -> None:
        """Regression: ensure_approval_center must restart daemon when healthz probe fails."""
        guard_home = tmp_path / "guard"
        guard_home.mkdir()
        alive_pid = os.getpid()
        stale_locator = ApprovalCenterLocator(
            guard_home=guard_home,
            daemon_url="http://127.0.0.1:6174",
            approval_url_base="http://127.0.0.1:6174",
            pid=alive_pid,
            started_at="2026-01-01T00:00:00Z",
            state_path=guard_home / "daemon-state.json",
        )
        write_approval_center_locator(guard_home, stale_locator)
        with (
            patch.object(manager_mod, "_guard_daemon_pid_matches_command", return_value=True),
            patch.object(manager_mod, "_approval_center_daemon_is_healthy", return_value=False),
            patch.object(manager_mod, "ensure_guard_daemon", return_value="http://127.0.0.1:7777") as mock_start,
        ):
            result = ensure_approval_center(guard_home)
        mock_start.assert_called_once_with(guard_home)
        assert result.daemon_url == "http://127.0.0.1:7777"

    def test_incompatible_daemon_version_triggers_restart(self, tmp_path: Path) -> None:
        """Regression: daemon returning 200 /healthz with stale compatibility_version must restart."""
        guard_home = tmp_path / "guard"
        guard_home.mkdir()
        alive_pid = os.getpid()
        stale_locator = ApprovalCenterLocator(
            guard_home=guard_home,
            daemon_url="http://127.0.0.1:6174",
            approval_url_base="http://127.0.0.1:6174",
            pid=alive_pid,
            started_at="2026-01-01T00:00:00Z",
            state_path=guard_home / "daemon-state.json",
        )
        write_approval_center_locator(guard_home, stale_locator)
        with (
            patch.object(manager_mod, "_guard_daemon_pid_matches_command", return_value=True),
            patch.object(manager_mod, "_approval_center_daemon_is_healthy", return_value=False),
            patch.object(manager_mod, "ensure_guard_daemon", return_value="http://127.0.0.1:8888") as mock_start,
        ):
            result = ensure_approval_center(guard_home)
        mock_start.assert_called_once_with(guard_home)
        assert result.daemon_url == "http://127.0.0.1:8888"


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


class TestFallbackCliCommandMigration:
    def test_old_row_without_fallback_cli_command_reads_as_none(self, tmp_path: Path) -> None:
        """T690: Old approval rows without fallback_cli_command must read back as None."""
        import sqlite3

        from codex_plugin_scanner.guard.store_approvals import (
            get_approval_request,
        )

        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("""
            create table approval_requests (
              request_id text primary key,
              harness text not null,
              artifact_id text not null,
              artifact_name text not null,
              artifact_type text not null,
              artifact_hash text not null,
              publisher text,
              policy_action text not null,
              recommended_scope text not null,
              changed_fields_json text not null,
              source_scope text not null,
              config_path text not null,
              workspace text,
              launch_target text,
              transport text,
              risk_summary text,
              risk_signals_json text not null default '[]',
              artifact_label text,
              source_label text,
              trigger_summary text,
              why_now text,
              launch_summary text,
              risk_headline text,
              action_envelope_json text,
              decision_v2_json text,
              review_command text not null,
              approval_url text not null,
              status text not null,
              resolution_action text,
              resolution_scope text,
              reason text,
              created_at text not null,
              resolved_at text
            )
        """)
        conn.execute("""
            insert into approval_requests (
              request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash,
              policy_action, recommended_scope, changed_fields_json, source_scope,
              config_path, review_command, approval_url, status, created_at, risk_signals_json
            ) values (
              'req-legacy', 'codex', 'art-legacy', 'legacy-artifact', 'artifact', 'abc123',
              'block', 'exact', '[]', 'local',
              '/tmp/config', 'hol-guard doctor', 'http://127.0.0.1:6174/#/approve/req-legacy',
              'pending', '2026-01-01T00:00:00Z', '[]'
            )
        """)
        conn.execute("alter table approval_requests add column fallback_cli_command text")
        conn.commit()

        row = get_approval_request(conn, "req-legacy")
        assert row is not None
        assert row["fallback_cli_command"] is None
        conn.close()


class TestApprovalTableFallbackCli:
    """T692-T694: Approval table Resolve column shows URL and fallback CLI command."""

    def _render_approval_table(self, items: list[dict[str, object]]) -> str:
        from io import StringIO

        from rich.console import Console

        from codex_plugin_scanner.guard.cli.render import _build_approval_table

        buf = StringIO()
        console = Console(file=buf, no_color=True, width=200)
        table = _build_approval_table(items, title=None)
        console.print(table)
        return buf.getvalue()

    def test_resolve_column_shows_url_and_fallback_cli_when_both_present(self) -> None:
        """T692: When approval_url and fallback_cli_command both set, Resolve shows both."""
        items = [
            {
                "request_id": "req-codex-001",
                "harness": "codex",
                "artifact_name": "my-tool",
                "changed_fields": [],
                "risk_summary": "low risk",
                "policy_action": "block",
                "approval_url": "http://127.0.0.1:6174/#/approve/req-codex-001",
                "fallback_cli_command": "hol-guard approvals approve req-codex-001",
                "review_command": "hol-guard approvals",
            }
        ]
        output = self._render_approval_table(items)
        assert "http://127.0.0.1:6174/#/approve/req-codex-001" in output
        assert "hol-guard approvals approve req-codex-001" in output

    def test_resolve_column_shows_only_url_when_no_fallback_cli(self) -> None:
        """T693: When only approval_url is set, Resolve shows just the URL."""
        items = [
            {
                "request_id": "req-claude-001",
                "harness": "claude",
                "artifact_name": "my-tool",
                "changed_fields": [],
                "risk_summary": "low risk",
                "policy_action": "block",
                "approval_url": "http://127.0.0.1:6174/#/approve/req-claude-001",
                "fallback_cli_command": None,
                "review_command": "hol-guard approvals",
            }
        ]
        output = self._render_approval_table(items)
        assert "http://127.0.0.1:6174/#/approve/req-claude-001" in output

    def test_resolve_column_falls_back_to_review_command_when_no_url(self) -> None:
        """T694: When no approval_url, Resolve shows review_command as before."""
        items = [
            {
                "request_id": "req-opencode-001",
                "harness": "opencode",
                "artifact_name": "my-tool",
                "changed_fields": [],
                "risk_summary": "low risk",
                "policy_action": "block",
                "approval_url": None,
                "fallback_cli_command": None,
                "review_command": "hol-guard approvals",
            }
        ]
        output = self._render_approval_table(items)
        assert "hol-guard approvals" in output


class TestFallbackCliCommandRewrite:
    """Regression: fallback_cli_command must be rewritten to new request_id on UPDATE (reuse path)."""

    def test_reused_request_id_rewrites_fallback_cli_command(self, tmp_path: Path) -> None:
        """Regression: When a pending row is reused, fallback_cli_command gets the new request_id."""
        import datetime
        import sqlite3 as _sqlite3

        from codex_plugin_scanner.guard.models import GuardApprovalRequest
        from codex_plugin_scanner.guard.store import GuardStore
        from codex_plugin_scanner.guard.store_approvals import (
            add_approval_request,
            get_approval_request,
        )

        guard_home = tmp_path / "guard"
        store = GuardStore(guard_home)

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        initial = GuardApprovalRequest(
            request_id="req-original-id",
            harness="codex",
            artifact_id="art-001",
            artifact_name="test-tool",
            artifact_hash="abc123",
            policy_action="block",
            recommended_scope="exact",
            changed_fields=(),
            source_scope="local",
            config_path="/tmp/config",
            review_command="hol-guard approvals req-original-id",
            approval_url="http://127.0.0.1:6174/#/approve/req-original-id",
            fallback_cli_command="hol-guard approvals approve req-original-id",
        )

        conn = _sqlite3.connect(str(store.path))
        conn.row_factory = _sqlite3.Row
        row_id1 = add_approval_request(conn, initial, now)

        updated = dataclasses.replace(
            initial,
            request_id="req-new-id",
            review_command="hol-guard approvals req-new-id",
            approval_url="http://127.0.0.1:6174/#/approve/req-new-id",
            fallback_cli_command="hol-guard approvals approve req-new-id",
        )
        row_id2 = add_approval_request(conn, updated, now)
        assert row_id2 == row_id1, "Must reuse existing pending row"

        row = get_approval_request(conn, row_id1)
        assert row is not None
        assert row["fallback_cli_command"] is not None
        assert row_id1 in row["fallback_cli_command"], (
            "fallback_cli_command must be rewritten to contain the original (stored) request_id"
        )
        conn.close()
