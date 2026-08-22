"""Codex/Grok hook approval URLs must carry a scoped session token."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.approval_hook_copy import join_native_hook_reason, live_hook_approval_context
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import (
    _native_approval_center_context,
    _native_hook_reason_for_harness,
)
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.store import GuardStore


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_daemon_token(guard_home: Path, token: str) -> None:
    guard_home.mkdir(parents=True, exist_ok=True)
    guard_home.chmod(0o700)
    token_path = guard_home / "daemon-auth-token"
    token_path.write_text(token, encoding="utf-8")
    token_path.chmod(0o600)


def test_stored_hook_copy_does_not_include_guard_token() -> None:
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


def test_live_hook_copy_adds_scoped_token_on_loopback(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    _write_daemon_token(guard_home, "secret-daemon-token")
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
    live = live_hook_approval_context(payload, harness="codex", guard_home=guard_home)
    assert live is not None
    assert "secret-daemon-token" not in live
    start = live.index("http://")
    review_url = live[start : live.index(". After you choose")]
    fragment = parse_qs(urlparse(review_url).fragment)
    assert fragment["guard-token"][0].startswith("gld1.")


def test_hook_reason_does_not_repeat_untokenized_approval_url() -> None:
    untokenized = (
        "Open HOL Guard to approve or keep this blocked: http://127.0.0.1:5474/requests/req-1. "
        "After you choose, retry the same Grok action."
    )
    tokenized = (
        "Open HOL Guard to approve or keep this blocked: "
        "http://127.0.0.1:5474/requests/req-1#guard-token=gld1.abc.def. "
        "After you choose, retry the same Grok action."
    )
    joined = join_native_hook_reason(untokenized, tokenized)
    grok_reason = _native_hook_reason_for_harness("grok", untokenized, tokenized)
    assert joined == tokenized
    assert grok_reason == tokenized
    assert joined.count("http://") == 1
    assert "guard-token=" in grok_reason


def test_hook_reason_keeps_policy_copy_with_one_tokenized_url() -> None:
    policy = (
        "HOL Guard needs your approval before this action can run. "
        "Open HOL Guard to approve or keep this blocked: http://127.0.0.1:5474/requests/req-1. "
        "After you choose, retry the same Codex action."
    )
    tokenized = (
        "Open HOL Guard to approve or keep this blocked: "
        "http://127.0.0.1:5474/requests/req-1#guard-token=gld1.abc.def. "
        "After you choose, retry the same Codex action."
    )
    joined = join_native_hook_reason(policy, tokenized)
    assert "needs your approval" in joined.lower()
    assert joined.count("http://") == 1
    assert "guard-token=" in joined
    assert "http://127.0.0.1:5474/requests/req-1." not in joined


def test_live_hook_copy_does_not_token_external_urls(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    _write_daemon_token(guard_home, "secret-daemon-token")
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
    live = live_hook_approval_context(payload, harness="codex", guard_home=guard_home)
    assert live is not None
    assert "https://example.invalid/approvals/req-ext-1" in live
    assert "guard-token=" not in live


def test_load_reconciles_watch_posture_when_mode_is_still_prompt(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'protection_posture = "watch"\nmode = "prompt"\nsecurity_level = "balanced"\n',
    )
    config = load_guard_config(guard_home)
    assert config.protection_posture == "watch"
    assert config.mode == "observe"


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
