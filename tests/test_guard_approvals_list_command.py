"""Tests for the read-only 'hol-guard approvals list' command."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import approval_commands as approval_commands_module
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


def _make_request(*, request_id: str) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id="codex:project:tool",
        artifact_name="Test tool",
        artifact_hash="hash-abc",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/tmp/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
    )


class TestApprovalsListCommand:
    """'hol-guard approvals list' prints the queue without opening the approval center."""

    def test_list_prints_the_queue_and_never_opens_the_browser(self, tmp_path: Path, monkeypatch, capsys) -> None:
        home_dir = tmp_path / "guard-home"
        store = GuardStore(home_dir)
        store.add_approval_request(_make_request(request_id="req-list-1"), "2026-01-01T00:00:00Z")
        opened_urls: list[str] = []
        monkeypatch.setattr(
            approval_commands_module,
            "load_guard_daemon_url",
            lambda _guard_home: "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            approval_commands_module,
            "open_browser_url",
            lambda url: opened_urls.append(url) or True,
        )

        rc = main(["guard", "approvals", "list", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert opened_urls == []
        assert "auto_open" not in output
        assert output["pending_count"] == 1
        assert output["next_request_id"] == "req-list-1"

    def test_list_resolves_nothing(self, tmp_path: Path, capsys) -> None:
        home_dir = tmp_path / "guard-home"
        store = GuardStore(home_dir)
        store.add_approval_request(_make_request(request_id="req-list-2"), "2026-01-01T00:00:00Z")

        rc = main(["guard", "approvals", "list", "--home", str(home_dir), "--json"])
        capsys.readouterr()

        assert rc == 0
        assert store.get_approval_request("req-list-2")["status"] == "pending"
