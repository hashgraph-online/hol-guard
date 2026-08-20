"""Codex/Grok hook approval URLs must carry a scoped session token."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _native_approval_center_context
from codex_plugin_scanner.guard.store import GuardStore


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_native_approval_center_context_adds_scoped_token_only_when_requested() -> None:
    payload = {
        "approval_center_url": "http://127.0.0.1:5474",
        "approval_requests": [
            {
                "request_id": "req-codex-1",
                "approval_url": "http://127.0.0.1:5474/requests/req-codex-1",
            }
        ],
        "primary_approval_url": "http://127.0.0.1:5474/requests/req-codex-1",
    }
    stored = _native_approval_center_context(payload, harness="codex")
    assert stored is not None
    assert "http://127.0.0.1:5474/requests/req-codex-1" in stored
    assert "guard-token=" not in stored

    live = _native_approval_center_context(
        payload,
        harness="codex",
        session_auth_token="secret-daemon-token",
    )
    assert live is not None
    assert "Open HOL Guard to approve or keep this blocked:" in live
    assert "secret-daemon-token" not in live
    start = live.index("http://")
    review_url = live[start : live.index(". After you choose")]
    fragment = parse_qs(urlparse(review_url).fragment)
    assert fragment["guard-token"][0].startswith("gld1.")


def test_native_approval_center_context_does_not_token_external_urls() -> None:
    payload = {
        "approval_center_url": "https://example.invalid/approvals",
        "approval_requests": [
            {
                "request_id": "req-ext-1",
                "approval_url": "https://example.invalid/approvals/req-ext-1",
            }
        ],
        "primary_approval_url": "https://example.invalid/approvals/req-ext-1",
    }
    live = _native_approval_center_context(
        payload,
        harness="codex",
        session_auth_token="secret-daemon-token",
    )
    assert live is not None
    assert "https://example.invalid/approvals/req-ext-1" in live
    assert "guard-token=" not in live


def test_watch_posture_with_stale_prompt_mode_does_not_block_codex_hook(tmp_path: Path, capsys) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    payload_path = workspace_dir / "hook-event.json"
    _write_text(
        home_dir / "config.toml",
        'protection_posture = "watch"\nmode = "prompt"\n',
    )
    _write_text(
        payload_path,
        json.dumps(
            {
                "session_id": "session-1",
                "turn_id": "turn-1",
                "cwd": str(workspace_dir),
                "hook_event_name": "PreToolUse",
                "model": "gpt-5.4",
                "permission_mode": "bypassPermissions",
                "tool_name": "Bash",
                "tool_input": {"command": "echo MALICIOUS > dangerous-marker.json"},
                "tool_use_id": "call-1",
            }
        ),
    )

    rc = main(
        [
            "guard",
            "hook",
            "--harness",
            "codex",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--event-file",
            str(payload_path),
        ]
    )
    captured = capsys.readouterr()
    store = GuardStore(home_dir)

    assert rc == 0
    assert captured.out == ""
    pending = store.list_approval_requests(limit=5)
    assert len(pending) == 1
    assert pending[0]["scanner_evidence"][-1]["authoritative_action"] == "allow"
