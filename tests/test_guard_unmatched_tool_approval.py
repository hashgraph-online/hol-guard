from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    is_explicitly_benign_tool_action_request,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_signed_approval_fixtures import write_synthetic_daemon_auth_token


@pytest.mark.parametrize(
    "command",
    (
        "date",
        "date -u '+%Y-%m-%dT%H:%M:00Z'",
        "date --utc +%s",
    ),
)
def test_bounded_date_queries_are_benign(tmp_path: Path, command: str) -> None:
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )


@pytest.mark.parametrize(
    "command",
    (
        "date -s tomorrow",
        "date --set=tomorrow",
        "date +%s +%N",
        "date -f timestamps.txt",
    ),
)
def test_date_mutations_and_file_reads_still_require_review(tmp_path: Path, command: str) -> None:
    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )


def test_codex_unmatched_tool_block_returns_real_review_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    workspace = tmp_path / "x-ads-api-tools"
    workspace.mkdir()
    guard_home.mkdir()
    write_synthetic_daemon_auth_token(guard_home)
    (guard_home / "config.toml").write_text(
        'mode = "enforce"\nsecurity_level = "balanced"\ndefault_action = "require-reapproval"\n'
    )
    event_path = tmp_path / "hook-event.json"
    event_path.write_text(
        json.dumps(
            {
                "session_id": "session-1",
                "turn_id": "turn-1",
                "cwd": str(workspace),
                "hook_event_name": "PreToolUse",
                "model": "gpt-5.6-sol",
                "permission_mode": "bypassPermissions",
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        'node xads.mjs line-items --account-id=example -H "Authorization: Bearer secret-token-value"'
                    ),
                },
                "tool_use_id": "call-1",
            }
        )
    )
    monkeypatch.setenv("CODEX_MANAGED_BY_BUN", "1")
    monkeypatch.setattr(
        guard_commands_module,
        "schedule_guard_daemon_ensure",
        lambda _guard_home, **_kwargs: "http://127.0.0.1:4455",
    )
    monkeypatch.setattr(
        guard_commands_module,
        "load_guard_surface_daemon_client",
        lambda _guard_home: (_ for _ in ()).throw(RuntimeError("daemon unavailable")),
    )

    result = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(guard_home),
            "--workspace",
            str(workspace),
            "--event-file",
            str(event_path),
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    pending = GuardStore(guard_home).list_approval_requests(limit=5)

    assert result == 0, payload
    assert "hookSpecificOutput" in payload, payload
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert len(pending) == 1, payload
    reason = payload["hookSpecificOutput"]["permissionDecisionReason"]
    assert "Open HOL Guard to approve or keep this blocked:" in reason
    assert "guard-token=gld1." in reason
    assert "Approve it in HOL Guard, then retry." not in reason
    assert pending[0]["artifact_type"] == "tool_action_request"
    assert str(pending[0]["approval_url"]).endswith(f"/requests/{pending[0]['request_id']}")
    pending_json = json.dumps(pending[0])
    assert "secret-token-value" not in pending_json
    assert "Bearer *****" in pending_json
