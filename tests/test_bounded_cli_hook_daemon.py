from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import bounded_cli_hook_bridge, bounded_cli_hook_daemon
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult

from .bounded_cli_hook_test_support import config as _config
from .bounded_cli_hook_test_support import runner_result as _runner_result


def test_grok_should_block_respects_guard_event_contract() -> None:
    from codex_plugin_scanner.guard.adapters.grok_hooks import grok_hook_should_block

    assert grok_hook_should_block(policy_action="block", event_name="UserPromptSubmit") is False
    assert grok_hook_should_block(policy_action="block", event_name="PreToolUse") is True
    assert grok_hook_should_block(policy_action="allow", event_name="PreToolUse") is False


def test_grok_bridge_rewrites_daemon_review_after_wait(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_plugin_scanner.guard.adapters import grok_approval_resume

    monkeypatch.setattr(
        grok_approval_resume,
        "wait_for_grok_live_approval",
        lambda **_kwargs: "allow",
    )
    stdout, _stderr, code = bounded_cli_hook_daemon._apply_grok_bridge_approval_wait(
        guard_home=tmp_path / "guard-home",
        harness="grok",
        input_text=json.dumps({"hook_event_name": "PreToolUse"}),
        stdout=json.dumps(
            {
                "decision": "deny",
                "policy_action": "review",
                "approval_requests": [{"request_id": "req-1"}],
            }
        ),
        stderr="",
        exit_code=2,
    )
    assert code == 0
    assert json.loads(stdout)["decision"] == "allow"


def test_grok_daemon_review_translation_keeps_wait_metadata() -> None:
    stdout, _stderr, code = bounded_cli_hook_daemon._daemon_response_to_native(
        {
            "policy_action": "review",
            "reason": "needs review",
            "approval_requests": [{"request_id": "req-1"}],
            "primary_approval_request_id": "req-1",
        },
        harness="grok",
        event_name="PreToolUse",
    )
    payload = json.loads(stdout)
    assert code == 2
    assert payload["decision"] == "deny"
    assert payload["policy_action"] == "review"
    assert payload["approval_requests"] == [{"request_id": "req-1"}]
    assert payload["primary_approval_request_id"] == "req-1"


@pytest.mark.parametrize(
    "event_name",
    [
        "UserPromptSubmit",
        "SessionStart",
        "SessionEnd",
        "SubagentStart",
        "SubagentStop",
        "PostToolUse",
        "PermissionDenied",
    ],
)
def test_grok_daemon_empty_observe_response_matches_native_success(event_name: str) -> None:
    from codex_plugin_scanner.guard.adapters.grok_hooks import grok_hook_response_from_guard

    native = grok_hook_response_from_guard(
        policy_action="allow",
        reason="",
        event_name=event_name,
    )
    stdout, stderr, code = bounded_cli_hook_daemon._daemon_response_to_native(
        native,
        harness="grok",
        event_name=event_name,
    )

    assert json.loads(stdout) == native == {}
    assert stderr == ""
    assert code == 0


@pytest.mark.parametrize("use_daemon", [True, False])
def test_grok_benign_prompt_succeeds_via_daemon_and_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    use_daemon: bool,
) -> None:
    if use_daemon:

        class Response:
            status = 200

            def __enter__(self) -> Response:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def geturl(self) -> str:
                return "http://127.0.0.1:7777/v1/hooks/grok"

            def read(self, _limit: int) -> bytes:
                return b"{}"

        class Opener:
            def open(self, _request: object, *, timeout: float) -> Response:
                assert timeout > 0
                return Response()

        monkeypatch.setattr(
            bounded_cli_hook_daemon,
            "_daemon_hook_endpoint",
            lambda _guard_home, _harness: "http://127.0.0.1:7777/v1/hooks/grok",
        )
        monkeypatch.setattr(bounded_cli_hook_daemon, "_read_daemon_auth_token", lambda _guard_home: "token")
        monkeypatch.setattr(bounded_cli_hook_daemon, "_build_loopback_opener", lambda: Opener())
    else:
        monkeypatch.setattr(bounded_cli_hook_daemon, "try_daemon_hook", lambda **_kwargs: None)
    monkeypatch.setattr(
        bounded_cli_hook_bridge,
        "run_isolated_hook_process",
        _runner_result(BoundedHookProcessResult(0, "{}\n", False, False)),
    )
    output = io.StringIO()
    with redirect_stdout(output):
        returncode = bounded_cli_hook_bridge.run_bounded_cli_hook(
            _config(tmp_path, harness="grok"),
            input_text=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "Summarize public documentation."}),
        )

    assert returncode == 0
    assert json.loads(output.getvalue()) == {}


def test_grok_daemon_prompt_native_block_is_preserved() -> None:
    stdout, stderr, code = bounded_cli_hook_daemon._daemon_response_to_native(
        {"decision": "block", "reason": "Prompt blocked by HOL Guard."},
        harness="grok",
        event_name="UserPromptSubmit",
    )

    assert json.loads(stdout) == {"decision": "block", "reason": "Prompt blocked by HOL Guard."}
    assert stderr == ""
    assert code == 2


@pytest.mark.parametrize(
    "response",
    [
        {"unexpected": "nonempty"},
        {"policy_action": "invalid", "reason": "malformed prompt policy"},
    ],
)
def test_grok_daemon_nonempty_ambiguous_prompt_response_fails_closed(
    response: dict[str, object],
) -> None:
    stdout, _stderr, code = bounded_cli_hook_daemon._daemon_response_to_native(
        response,
        harness="grok",
        event_name="UserPromptSubmit",
    )

    payload = json.loads(stdout)
    assert code == 2
    assert payload["decision"] == "block"
    assert payload["reason"]


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"unexpected": "nonempty"},
        {"policy_action": "invalid", "reason": "malformed policy"},
    ],
)
def test_grok_daemon_ambiguous_pretool_response_fails_closed(response: dict[str, object]) -> None:
    stdout, _stderr, code = bounded_cli_hook_daemon._daemon_response_to_native(
        response,
        harness="grok",
        event_name="PreToolUse",
    )

    payload = json.loads(stdout)
    assert code == 2
    assert payload["decision"] == "deny"
    assert payload["policy_action"] == "block"


def test_grok_daemon_dangerous_pretool_block_keeps_reason() -> None:
    stdout, _stderr, code = bounded_cli_hook_daemon._daemon_response_to_native(
        {"policy_action": "block", "reason": "Credential file access is blocked."},
        harness="grok",
        event_name="PreToolUse",
    )

    payload = json.loads(stdout)
    assert code == 2
    assert payload == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "Credential file access is blocked.",
        },
        "decision": "deny",
        "policy_action": "block",
        "reason": "Credential file access is blocked.",
    }


def test_grok_bridge_clamps_wait_to_remaining_seconds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from codex_plugin_scanner.guard.adapters import grok_approval_resume

    seen: dict[str, object] = {}

    def capture(response: dict[str, object], **kwargs: object) -> dict[str, object]:
        seen["timeout_seconds"] = kwargs["timeout_seconds"]
        return response

    monkeypatch.setattr(grok_approval_resume, "apply_grok_pretool_approval_wait", capture)
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text("approval_wait_timeout_seconds = 80\n", encoding="utf-8")
    bounded_cli_hook_daemon._apply_grok_bridge_approval_wait(
        guard_home=guard_home,
        harness="grok",
        input_text=json.dumps({"hook_event_name": "PreToolUse"}),
        stdout=json.dumps({"decision": "deny", "policy_action": "review"}),
        stderr="",
        exit_code=2,
        timeout_seconds=2.9,
    )
    assert seen["timeout_seconds"] == 2


def test_grok_bridge_preserves_daemon_result_when_store_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sqlite3

    from codex_plugin_scanner.guard.adapters import grok_approval_resume

    def boom(*_args: object, **_kwargs: object) -> str:
        del _args, _kwargs
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(grok_approval_resume, "apply_grok_pretool_approval_wait", boom)
    original = json.dumps({"decision": "deny", "policy_action": "review"})
    stdout, stderr, code = bounded_cli_hook_daemon._apply_grok_bridge_approval_wait(
        guard_home=tmp_path / "guard-home",
        harness="grok",
        input_text=json.dumps({"hook_event_name": "PreToolUse"}),
        stdout=original,
        stderr="keep-stderr",
        exit_code=2,
    )
    assert stdout == original
    assert stderr == "keep-stderr"
    assert code == 2
