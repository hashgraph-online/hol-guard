"""Codex/Grok hook approval URLs must carry a scoped session token."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.approval_hook_copy import live_approval_review_url
from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import (
    _native_approval_center_context,
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


def test_stored_hook_copy_uses_primary_url_without_approval_center_field() -> None:
    payload = {
        "primary_approval_url": "http://127.0.0.1:5474/requests/req-codex-2",
        "approval_request_id": "req-codex-2",
    }
    stored = _native_approval_center_context(payload, harness="codex")
    assert stored is not None
    assert "http://127.0.0.1:5474/requests/req-codex-2" in stored
    assert "Open HOL Guard to approve or keep this blocked:" in stored


def test_live_approval_review_url_tokens_loopback(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    _write_daemon_token(guard_home, "secret-daemon-token")
    review_url = "http://127.0.0.1:5474/requests/req-live-1"
    live = live_approval_review_url(review_url, guard_home=guard_home)
    assert live.startswith(review_url)
    assert "secret-daemon-token" not in live
    fragment = parse_qs(urlparse(live).fragment)
    assert fragment["guard-token"][0].startswith("gld1.")


def test_load_reconciles_watch_posture_when_mode_is_still_prompt(tmp_path: Path) -> None:
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'protection_posture = "watch"\nmode = "prompt"\nsecurity_level = "balanced"\n',
    )
    config = load_guard_config(guard_home)
    assert config.protection_posture == "watch"
    assert config.mode == "observe"


@pytest.mark.usefixtures("native_hook_force")
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
    output = json.loads(captured.out)
    assert output["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert output["policy_action"] == "warn"
    assert store.list_approval_requests(limit=5) == []


def test_unavailable_runtime_leaves_review_copy_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runner_authority
    from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _localize_pending_approval_copy

    def unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise native_runner_authority.NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", unavailable)
    review_url = "http://127.0.0.1:5474/requests/req-codex-3"
    payload: dict[str, object] = {
        "primary_approval_url": review_url,
        "decision_v2_json": {"action": "ask", "harness_message": "Held for review."},
        "supply_chain_evaluation": {"user_copy": {"harness_message": "Package held."}},
    }
    assert _native_approval_center_context(payload, harness="codex") is None
    _localize_pending_approval_copy(payload, harness="codex")
    assert payload["decision_v2_json"] == {"action": "ask", "harness_message": "Held for review."}
    assert payload["supply_chain_evaluation"] == {
        "user_copy": {"harness_message": "Package held.", "dashboard_url": review_url}
    }


def test_a_long_approval_queue_is_routed_in_bounded_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runner_authority
    from codex_plugin_scanner.guard.cli import commands_support_runtime_policy as policy

    calls: list[dict[str, object]] = []

    def route(kind: str, args: dict[str, object]) -> dict[str, object]:
        assert kind == "approval_copy"
        calls.append(args)
        if len(calls) == 2:
            raise native_runner_authority.NativeRunnerAuthorityError("native_runner_authority_invalid")
        batch = args["decisions"]
        assert isinstance(batch, list)
        return {
            "review_context": "Open HOL Guard.",
            "decisions": [{"harness_message": "Routed."} for _ in batch],
            "user_copy_message": "Routed copy." if args["user_copy_message"] else None,
        }

    monkeypatch.setattr(native_runner_authority, "native_runner_authority", route)
    # One decision per request.
    monkeypatch.setattr(policy, "_APPROVAL_COPY_BATCH_BYTES", 1)
    queued = [{"decision_v2_json": {"action": "allow", "harness_message": f"Held {index}."}} for index in range(2)]
    payload: dict[str, object] = {
        "primary_approval_url": "http://127.0.0.1:5474/requests/req-codex-4",
        "decision_v2_json": {"action": "allow", "harness_message": "Held."},
        "approval_requests": queued,
        "supply_chain_evaluation": {"user_copy": {"harness_message": "Package held."}},
    }
    policy._localize_pending_approval_copy(payload, harness="codex")
    assert [call["user_copy_message"] for call in calls] == ["Package held.", None, None]
    assert payload["decision_v2_json"] == {"action": "allow", "harness_message": "Routed."}
    # The refused batch keeps its original copy; the next one still routes.
    assert [item["decision_v2_json"]["harness_message"] for item in queued] == ["Held 0.", "Routed."]
    user_copy = payload["supply_chain_evaluation"]
    assert isinstance(user_copy, dict)
    assert user_copy["user_copy"]["harness_message"] == "Routed copy."
