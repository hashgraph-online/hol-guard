"""Installed lab checks harness exit contracts and explicit native denials."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


def _lab() -> ModuleType:
    path = Path(__file__).parent / "dockerlabs/command-extension-analytics/installed_server.py"
    spec = importlib.util.spec_from_file_location("installed_dockerlab_server", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("policy_action", "permission_decision", "accepted"),
    [
        ("review", "deny", True),
        (None, "deny", True),
        ("warn", "allow", False),
        ("warn", "deny", False),
        ("review", "allow", False),
    ],
)
@pytest.mark.parametrize("harness", ["codex", "claude-code"])
def test_installed_native_status_requires_explicit_denial(
    harness: str,
    policy_action: str | None,
    permission_decision: str,
    accepted: bool,
) -> None:
    lab = _lab()
    response: dict[str, object] = {"hookSpecificOutput": {"permissionDecision": permission_decision}}
    if policy_action is not None:
        response["policy_action"] = policy_action
    completed = subprocess.CompletedProcess([], 0, json.dumps(response), "")
    lab.subprocess = SimpleNamespace(run=lambda *_args, **_kwargs: completed)

    if accepted:
        lab._run_installed_hook(harness, {"hook_event_name": "PreToolUse"}, expect_denial=True)
    else:
        with pytest.raises(RuntimeError, match=f"installed {harness} hook returned 0, expected 0"):
            lab._run_installed_hook(harness, {"hook_event_name": "PreToolUse"}, expect_denial=True)


@pytest.mark.parametrize("response", ["{}", "[]", "not-json", '{"hookSpecificOutput": {"permissionDecision": "ask"}}'])
def test_installed_native_status_rejects_missing_denial(response: str) -> None:
    lab = _lab()
    completed = subprocess.CompletedProcess([], 0, response, "")
    lab.subprocess = SimpleNamespace(run=lambda *_args, **_kwargs: completed)
    with pytest.raises(RuntimeError, match="returned 0, expected 0"):
        lab._run_installed_hook("claude-code", {"hook_event_name": "PreToolUse"}, expect_denial=True)


@pytest.mark.parametrize("status", [0, 1, 2])
def test_installed_cursor_denial_requires_exit_two(status: int) -> None:
    lab = _lab()
    completed = subprocess.CompletedProcess([], status, "{}", "")
    lab.subprocess = SimpleNamespace(run=lambda *_args, **_kwargs: completed)
    if status == 2:
        lab._run_installed_hook("cursor", {"hook_event_name": "PreToolUse"}, expect_denial=True)
    else:
        with pytest.raises(RuntimeError, match=f"returned {status}, expected 2"):
            lab._run_installed_hook("cursor", {"hook_event_name": "PreToolUse"}, expect_denial=True)


@pytest.mark.parametrize(
    ("harness", "action", "decision", "accepted"),
    [
        ("claude-code", "review", "ask", True),
        ("claude-code", "require-reapproval", "ask", True),
        ("claude-code", "review", "allow", False),
        ("claude-code", "warn", "ask", False),
        ("claude-code", "block", "ask", False),
        ("codex", "review", "ask", False),
    ],
)
def test_installed_claude_review_requires_native_approval(
    harness: str, action: str, decision: str, accepted: bool,
) -> None:
    lab = _lab()
    response = {"policy_action": action, "hookSpecificOutput": {"permissionDecision": decision}}
    completed = subprocess.CompletedProcess([], 0, json.dumps(response), "")
    lab.subprocess = SimpleNamespace(run=lambda *_args, **_kwargs: completed)
    if accepted:
        lab._run_installed_hook(harness, {"hook_event_name": "PreToolUse"}, expect_approval=True)
    else:
        with pytest.raises(RuntimeError):
            lab._run_installed_hook(harness, {"hook_event_name": "PreToolUse"}, expect_approval=True)


@pytest.mark.parametrize("prefix", ["#", "#guardDaemon=http%3A%2F%2F127.0.0.1%3A4781&", "?"])
def test_installed_hook_diagnostic_redacts_approval_tokens(prefix: str) -> None:
    lab = _lab()
    value = f'approve http://127.0.0.1/requests/fixture{prefix}guard-token=fixture-token&view=inbox next'
    assert lab._safe_hook_diagnostic(value) == value.replace("fixture-token", "[REDACTED]")
