"""Tests for ApprovalCenterLocator helpers (T676-T683, T688-T694)."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

manager_mod = pytest.importorskip(
    "codex_plugin_scanner.guard.native_daemon_manage",
    reason="Guard daemon manager not importable",
)

ApprovalCenterLocator = manager_mod.ApprovalCenterLocator
read_approval_center_locator = manager_mod.read_approval_center_locator


def write_approval_center_locator(guard_home: Path, locator: ApprovalCenterLocator) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    payload = {
        "guard_home": str(locator.guard_home),
        "daemon_url": locator.daemon_url,
        "approval_url_base": locator.approval_url_base,
        "pid": locator.pid,
        "started_at": locator.started_at,
        "state_path": str(locator.state_path),
    }
    path = guard_home / "approval-center-locator.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    path.chmod(0o600)




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

        from codex_plugin_scanner.guard.models import GuardApprovalRequest
        from codex_plugin_scanner.guard.store import GuardStore

        guard_home = tmp_path / "guard"
        GuardStore(guard_home).add_approval_request(
            GuardApprovalRequest(
                request_id="req-legacy",
                harness="codex",
                artifact_id="art-legacy",
                artifact_name="legacy-artifact",
                artifact_hash="abc123",
                policy_action="block",
                recommended_scope="exact",
                changed_fields=(),
                source_scope="local",
                config_path="/tmp/config",
                review_command="hol-guard doctor",
                approval_url="http://127.0.0.1:6174/#/approve/req-legacy",
                fallback_cli_command="hol-guard approvals approve req-legacy",
            ),
            "2026-01-01T00:00:00Z",
        )
        legacy = sqlite3.connect(guard_home / "guard.db")
        # Recreate a pre-upgrade table: same row, no fallback column. Triggers
        # added after the column read it, so they go first.
        triggers = legacy.execute(
            "select name from sqlite_master where type = 'trigger' and sql like '%fallback_cli_command%'"
        ).fetchall()
        for (trigger,) in triggers:
            legacy.execute(f'drop trigger "{trigger}"')
        legacy.execute("alter table approval_requests drop column fallback_cli_command")
        # A store that old is also missing later migrations, so reopening it runs
        # the full schema pass that adds the column back with no value.
        legacy.execute("delete from schema_migrations where version = 20")
        legacy.commit()
        legacy.close()

        row = GuardStore(guard_home).get_approval_request("req-legacy")
        assert row is not None
        assert row["fallback_cli_command"] is None


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

        from codex_plugin_scanner.guard.models import GuardApprovalRequest
        from codex_plugin_scanner.guard.store import GuardStore

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

        row_id1 = store.add_approval_request(initial, now)

        updated = dataclasses.replace(
            initial,
            request_id="req-new-id",
            review_command="hol-guard approvals req-new-id",
            approval_url="http://127.0.0.1:6174/#/approve/req-new-id",
            fallback_cli_command="hol-guard approvals approve req-new-id",
        )
        row_id2 = store.add_approval_request(updated, now)
        assert row_id2 == row_id1, "Must reuse existing pending row"

        row = store.get_approval_request(row_id1)
        assert row is not None
        assert row["fallback_cli_command"] is not None
        assert row_id1 in row["fallback_cli_command"], (
            "fallback_cli_command must be rewritten to contain the original (stored) request_id"
        )
