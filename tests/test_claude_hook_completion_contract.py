"""Hook verdicts travel through stdout, not the process completion status."""

from __future__ import annotations

import io
import json
from unittest.mock import Mock
from urllib.parse import urlencode

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge


def _invoke(tmp_path):
    return bridge.main(
        state_path=tmp_path / "daemon-state.json",
        fallback_daemon_url="http://127.0.0.1:5474/",
        fallback_command=(),
        query=urlencode({"guard-home": str(tmp_path)}),
    )


@pytest.mark.parametrize("decision", ["allow", "deny"])
@pytest.mark.parametrize("suppressed", [False, True])
def test_daemon_output_keeps_decision_and_completion_separate(tmp_path, monkeypatch, capsys, decision, suppressed) -> None:
    response = json.dumps({"hookSpecificOutput": {"permissionDecision": decision}})
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO("{}"))
    monkeypatch.setattr(bridge, "_recovery_command", Mock(return_value=()))
    monkeypatch.setattr(bridge, "_daemon_url", Mock(return_value="http://127.0.0.1:5474/"))
    monkeypatch.setattr(bridge, "_post_to_loopback_daemon", Mock(return_value=response))
    monkeypatch.setattr(bridge, "_valid_hook_json_or_degraded", Mock(return_value=response))
    monkeypatch.setattr(bridge, "_should_suppress_output", Mock(return_value=suppressed))

    assert _invoke(tmp_path) == 0
    assert capsys.readouterr().out == ("" if suppressed else response)


def test_oversized_input_denies_without_contacting_daemon(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(bridge, "_MAX_HOOK_INPUT_BYTES", 4)
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO("x" * 5))
    post = Mock(side_effect=AssertionError("must not contact daemon"))
    monkeypatch.setattr(bridge, "_post_to_loopback_daemon", post)

    assert _invoke(tmp_path) == 0
    assert capsys.readouterr().out == bridge._limit_denied("hook input", "PreToolUse")
    post.assert_not_called()


def test_local_fallback_denial_is_emitted_once(tmp_path, monkeypatch, capsys) -> None:
    response = '{"hookSpecificOutput":{"permissionDecision":"deny"}}'
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO("{}"))
    monkeypatch.setattr(bridge, "_recovery_command", Mock(return_value=()))
    monkeypatch.setattr(bridge, "_daemon_url", Mock(side_effect=ValueError("invalid state")))
    monkeypatch.setattr(bridge, "_daemon_failure_kind", Mock(return_value="unrecoverable"))
    monkeypatch.setattr(bridge, "_daemon_failure_is_recoverable", Mock(return_value=False))
    fallback = Mock(return_value=response)
    monkeypatch.setattr(bridge, "_run_local_fallback", fallback)

    assert _invoke(tmp_path) == 0
    assert capsys.readouterr().out == response
    fallback.assert_called_once()
