"""Claude hook exit status must not alter the protocol response or fallback flow."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge


@pytest.fixture
def hook_calls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Mock]:
    calls = {
        "state_path_for_query": Mock(return_value=tmp_path / "daemon-state.json"),
        "_recovery_command": Mock(return_value=("recovery",)),
        "_daemon_url": Mock(return_value="http://127.0.0.1:5474/"),
        "_assert_loopback_http_url": Mock(),
        "_post_to_loopback_daemon": Mock(return_value='{"decision":"allow"}'),
        "_valid_hook_json_or_degraded": Mock(side_effect=lambda value, **_kwargs: value),
        "_daemon_failure_reason": Mock(return_value="fixture failure"),
        "_daemon_failure_kind": Mock(return_value="unavailable"),
        "_daemon_failure_is_recoverable": Mock(return_value=False),
        "_authenticated_control_plane_failure": Mock(return_value='{"decision":"deny","source":"auth"}'),
        "_recover_retry_or_fallback": Mock(return_value='{"decision":"deny","source":"retry"}'),
        "_run_local_fallback": Mock(return_value='{"decision":"deny","source":"local"}'),
        "_should_suppress_output": Mock(return_value=False),
    }
    for name, call in calls.items():
        monkeypatch.setattr(bridge, name, call)
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO('{"hook_event_name":"PreToolUse"}'))
    return calls


def run_hook(tmp_path: Path) -> int:
    return bridge.main(
        state_path=tmp_path / "daemon-state.json",
        fallback_daemon_url="http://127.0.0.1:5474/",
        fallback_command=("fallback",),
        query="fixture=1",
    )


@pytest.mark.parametrize(
    ("response", "suppress", "expected"),
    [
        ("{}", False, "{}"),
        ("", False, "{}"),
        ("  ", False, "{}"),
        ('{"decision":"deny"}', False, '{"decision":"deny"}'),
        ("{}", True, ""),
    ],
)
def test_success_writes_once_or_suppresses_only_success(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    hook_calls: dict[str, Mock],
    response: str,
    suppress: bool,
    expected: str,
) -> None:
    hook_calls["_post_to_loopback_daemon"].return_value = response
    hook_calls["_should_suppress_output"].return_value = suppress
    assert run_hook(tmp_path) == 0
    assert capsys.readouterr().out == expected
    hook_calls["_post_to_loopback_daemon"].assert_called_once()
    hook_calls["_should_suppress_output"].assert_called_once()
    hook_calls["_run_local_fallback"].assert_not_called()


@pytest.mark.parametrize("failure", ["state", "authenticated", "recoverable", "unavailable"])
def test_failure_output_is_never_suppressed_or_replaced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], hook_calls: dict[str, Mock], failure: str
) -> None:
    hook_calls["_should_suppress_output"].return_value = True
    selected = "_run_local_fallback"
    if failure == "state":
        hook_calls["state_path_for_query"].side_effect = ValueError("invalid state")
    else:
        hook_calls["_post_to_loopback_daemon"].side_effect = OSError("unavailable")
        if failure == "authenticated":
            hook_calls["_daemon_failure_kind"].return_value = "authenticated-control-plane-failure"
            selected = "_authenticated_control_plane_failure"
        elif failure == "recoverable":
            hook_calls["_daemon_failure_is_recoverable"].return_value = True
            selected = "_recover_retry_or_fallback"
    assert run_hook(tmp_path) == 0
    assert capsys.readouterr().out == hook_calls[selected].return_value
    hook_calls[selected].assert_called_once()
    hook_calls["_should_suppress_output"].assert_not_called()
    if failure == "state":
        hook_calls["_recovery_command"].assert_not_called()
        hook_calls["_post_to_loopback_daemon"].assert_not_called()


@pytest.mark.parametrize(
    "event", ["PreToolUse", "PermissionRequest", "UserPromptSubmit", "PostToolUse", "Stop", "unknown"]
)
def test_oversized_input_preserves_event_denial_without_contacting_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    hook_calls: dict[str, Mock],
    event: str,
) -> None:
    monkeypatch.setattr(bridge, "_MAX_HOOK_INPUT_BYTES", 1)
    monkeypatch.setattr(bridge.sys, "stdin", io.StringIO("é"))
    monkeypatch.setattr(bridge, "_event_name", Mock(return_value=event))
    denied = Mock(return_value='{"decision":"deny","source":"limit"}')
    monkeypatch.setattr(bridge, "_limit_denied", denied)
    assert run_hook(tmp_path) == 0
    assert capsys.readouterr().out == denied.return_value
    denied.assert_called_once_with("hook input", "PreToolUse" if event == "unknown" else event)
    hook_calls["state_path_for_query"].assert_not_called()
    hook_calls["_post_to_loopback_daemon"].assert_not_called()
