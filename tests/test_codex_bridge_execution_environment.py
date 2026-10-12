"""The Codex bridge must forward its own execution environment to the daemon."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from codex_plugin_scanner.guard.hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY


@pytest.mark.parametrize("event_name", ["PreToolUse", "PostToolUse", "UserPromptSubmit"])
def test_bridge_replaces_model_supplied_environment_with_its_own(
    monkeypatch: pytest.MonkeyPatch,
    event_name: str,
) -> None:
    raw = json.dumps(
        {
            "hook_event_name": event_name,
            "tool_input": {"command": "git status"},
            HOOK_EXECUTION_ENVIRONMENT_KEY: {"path": "/model-supplied"},
        }
    )
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(bridge, "_hook_input", lambda _limit: raw)

    bound = bridge._bound_hook_input({event_name: 10})

    assert bound is not None
    forwarded = json.loads(bound[1])
    environment = forwarded[HOOK_EXECUTION_ENVIRONMENT_KEY]
    assert environment["path"] == "/usr/bin:/bin"
    assert isinstance(environment["environment_digest"], str)
    assert len(environment["environment_digest"]) == 64
    assert forwarded["tool_input"] == {"command": "git status"}
