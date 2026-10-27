"""``hol-guard hook`` prints what the resident read from the daemon answer."""

from __future__ import annotations

import io
import json

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_native_authority as cli


def test_bridge_harness_prints_the_resident_rendering(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, object], str, float | None]] = []

    def rendered(harness, response, *, event_name, guard_home=None, deadline=None):
        del guard_home
        calls.append((harness, dict(response), event_name, deadline))
        return {"stdout": '{"decision":"deny"}', "stderr": "", "exit_code": 2}

    monkeypatch.setattr(cli, "native_cli_hook_emit", rendered)
    stream = io.StringIO()
    code = cli.emit_hook_review(
        "grok", {"policy_action": "block"}, event_name="PreToolUse", output_stream=stream, deadline=12.5
    )
    assert code == 2
    assert stream.getvalue() == '{"decision":"deny"}\n'
    assert calls == [("grok", {"policy_action": "block"}, "PreToolUse", 12.5)]


@pytest.mark.parametrize("answer", (None, {"stdout": 1, "stderr": "", "exit_code": 0}, {"exit_code": True}))
def test_bridge_harness_fails_closed_without_a_rendering(monkeypatch: pytest.MonkeyPatch, answer) -> None:
    monkeypatch.setattr(cli, "native_cli_hook_emit", lambda *_args, **_kwargs: answer)
    stream = io.StringIO()
    code = cli.emit_hook_review("kimi", {"policy_action": "allow"}, event_name="PreToolUse", output_stream=stream)
    payload = json.loads(stream.getvalue())
    assert code == 2
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize(("answer", "expected"), (({"policy_action": "allow"}, 0), (None, 2), ({}, 2)))
def test_other_harness_exits_with_the_named_policy_action(
    monkeypatch: pytest.MonkeyPatch, answer, expected: int
) -> None:
    monkeypatch.setattr(cli, "native_cli_hook_emit", lambda *_args, **_kwargs: answer)
    stream = io.StringIO()
    code = cli.emit_hook_review("cursor", {"policy_action": "allow"}, event_name="PreToolUse", output_stream=stream)
    assert json.loads(stream.getvalue()) == {"policy_action": "allow"}
    assert code == expected


@pytest.mark.parametrize("harness", ("cursor", "codex", "opencode"))
def test_an_unread_answer_to_an_event_that_cannot_pause_lets_the_turn_continue(
    monkeypatch: pytest.MonkeyPatch, harness: str
) -> None:
    # The fixed lifecycle envelope is printed when the resident is down, and
    # the render goes to the same resident; its outage must not block.
    deadlines: list[float | None] = []

    def unavailable(*_args, deadline=None, **_kwargs):
        deadlines.append(deadline)

    monkeypatch.setattr(cli, "native_cli_hook_emit", unavailable)
    stream = io.StringIO()
    code = cli.emit_hook_review(
        harness, {"continue": True}, event_name="PostToolUse", output_stream=stream, deadline=7.0
    )
    assert json.loads(stream.getvalue()) == {"continue": True}
    assert code == 0
    assert deadlines == [7.0]


def test_claude_code_never_asks_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(*_args, **_kwargs):
        raise AssertionError("claude-code reads its JSON only on exit 0")

    monkeypatch.setattr(cli, "native_cli_hook_emit", unexpected)
    stream = io.StringIO()
    assert cli.emit_hook_review("claude-code", {"decision": "block"}, event_name="Stop", output_stream=stream) == 0


def test_the_emit_render_ships_a_large_answer_under_its_own_budget(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from codex_plugin_scanner.guard import native_hook_render as render

    budgets: dict[str, int] = {}

    def resident(*, request, max_request_bytes, **_kwargs):
        budgets[str(request["kind"])] = max_request_bytes

    monkeypatch.setattr(render, "_resolve_digest_home", lambda home: home)
    monkeypatch.setattr(render, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(render, "_resident_request", resident)
    answer = {"policy_action": "block", "reason": '"x"' * (render._MAX_REQUEST_BYTES // 2)}
    assert render.native_cli_hook_emit("cursor", answer, event_name="PreToolUse", guard_home=tmp_path) is None
    assert render.native_render_cli("cli_document", "cursor", {}, guard_home=tmp_path) is None
    assert budgets == {
        "cli_hook_emit": render._CLI_HOOK_EMIT_MAX_REQUEST_BYTES,
        "cli_document": render._MAX_REQUEST_BYTES,
    }
