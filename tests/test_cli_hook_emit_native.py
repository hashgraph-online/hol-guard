"""``hol-guard hook`` prints what the resident read from the daemon answer."""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_native_authority as cli
from codex_plugin_scanner.guard.daemon.hook_fail_closed import fail_closed_response


def test_bridge_harness_prints_the_resident_rendering(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, object], str, float | None]] = []

    def rendered(harness, response, *, event_name, guard_home=None, deadline=None):
        del guard_home
        calls.append((harness, dict(response), event_name, deadline))
        return {"stdout": '{"decision":"deny"}', "stderr": "", "exit_code": 2}

    monkeypatch.setattr(cli, "native_cli_hook_emit", rendered)
    stream = io.StringIO()
    deadline = time.monotonic() + 30.0
    code = cli.emit_hook_review(
        "grok", {"policy_action": "block"}, event_name="PreToolUse", output_stream=stream, deadline=deadline
    )
    assert code == 2
    assert stream.getvalue() == '{"decision":"deny"}\n'
    assert calls == [("grok", {"policy_action": "block"}, "PreToolUse", deadline)]


@pytest.mark.parametrize("answer", (None, {"stdout": 1, "stderr": "", "exit_code": 0}, {"exit_code": True}))
def test_bridge_harness_fails_closed_without_a_rendering(monkeypatch: pytest.MonkeyPatch, answer) -> None:
    monkeypatch.setattr(cli, "native_cli_hook_emit", lambda *_args, **_kwargs: answer)
    stream = io.StringIO()
    code = cli.emit_hook_review("kimi", {"policy_action": "allow"}, event_name="PreToolUse", output_stream=stream)
    payload = json.loads(stream.getvalue())
    assert code == 2
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def _fail_closed_line(harness: str, event_name: str) -> str:
    return json.dumps(fail_closed_response(harness, event_name), ensure_ascii=True, separators=(",", ":")) + "\n"


@pytest.mark.parametrize("exit_code", (0, 2))
def test_other_harness_prints_the_resident_document(monkeypatch: pytest.MonkeyPatch, exit_code: int) -> None:
    calls: list[tuple[str, dict[str, object], str, float | None, bool]] = []
    printed = '{\n  "policy_action": "block",\n  "approval_url": "http://127.0.0.1/a#guard-token=Ab.c~d"\n}'

    def rendered(harness, response, *, event_name, guard_home=None, deadline=None, document=False):
        del guard_home
        calls.append((harness, dict(response), event_name, deadline, document))
        return {"stdout": printed, "exit_code": exit_code, "policy_action": "block"}

    monkeypatch.setattr(cli, "native_cli_hook_emit", rendered)
    stream = io.StringIO()
    deadline = time.monotonic() + 30.0
    code = cli.emit_hook_review(
        "cursor", {"policy_action": "block"}, event_name="PreToolUse", output_stream=stream, deadline=deadline
    )
    assert code == exit_code
    assert stream.getvalue() == printed + "\n"
    assert calls == [("cursor", {"policy_action": "block"}, "PreToolUse", deadline, True)]


@pytest.mark.parametrize(
    "answer",
    (
        None,
        # A resident that predates ``document`` names only the verdict.
        {"policy_action": "allow"},
        {},
        {"stdout": 1, "exit_code": 0},
        {"stdout": '{"policy_action":"allow"}', "exit_code": True},
        {"stdout": '{"policy_action":"allow"}'},
    ),
)
def test_other_harness_fails_closed_without_the_resident_document(monkeypatch: pytest.MonkeyPatch, answer) -> None:
    monkeypatch.setattr(cli, "native_cli_hook_emit", lambda *_args, **_kwargs: answer)
    stream = io.StringIO()
    code = cli.emit_hook_review("cursor", {"policy_action": "allow"}, event_name="PreToolUse", output_stream=stream)
    # Nothing reads the answer in Python: the allow is never printed.
    assert stream.getvalue() == _fail_closed_line("cursor", "PreToolUse")
    assert code == 2


@pytest.mark.parametrize("harness", ("cursor", "codex", "opencode"))
def test_an_unread_answer_to_an_event_that_cannot_pause_lets_the_turn_continue(
    monkeypatch: pytest.MonkeyPatch, harness: str
) -> None:
    # The fixed lifecycle envelope is printed when the resident is down; its
    # outage must not block.
    deadlines: list[float | None] = []

    def unavailable(*_args, deadline=None, **_kwargs):
        deadlines.append(deadline)

    monkeypatch.setattr(cli, "native_cli_hook_emit", unavailable)
    stream = io.StringIO()
    deadline = time.monotonic() + 30.0
    code = cli.emit_hook_review(
        harness, {"continue": True}, event_name="PostToolUse", output_stream=stream, deadline=deadline
    )
    assert stream.getvalue() == _fail_closed_line(harness, "PostToolUse")
    assert json.loads(stream.getvalue())["continue"] is True
    assert code == 0
    assert deadlines == [deadline]


def test_claude_code_prints_the_resident_document_with_its_status(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def rendered(*_args, document=False, **_kwargs):
        calls.append(document)
        return {"stdout": '{\n  "decision": "block"\n}', "exit_code": 0, "policy_action": "block"}

    monkeypatch.setattr(cli, "native_cli_hook_emit", rendered)
    stream = io.StringIO()
    assert cli.emit_hook_review("claude-code", {"decision": "block"}, event_name="Stop", output_stream=stream) == 0
    assert stream.getvalue() == '{\n  "decision": "block"\n}\n'
    assert calls == [True]


@pytest.mark.parametrize("event_name", ("PreToolUse", "Stop"))
def test_claude_code_exits_zero_when_the_resident_is_down(monkeypatch: pytest.MonkeyPatch, event_name: str) -> None:
    # Claude reads a hook's JSON only on exit 0, the fail-closed deny included.
    monkeypatch.setattr(cli, "native_cli_hook_emit", lambda *_args, **_kwargs: None)
    stream = io.StringIO()
    assert cli.emit_hook_review("claude-code", {"decision": "allow"}, event_name=event_name, output_stream=stream) == 0
    assert stream.getvalue() == _fail_closed_line("claude-code", event_name)


def test_the_document_request_names_this_home(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from codex_plugin_scanner.guard import native_hook_render as render

    sent: list[dict[str, object]] = []

    def native_render_cli(kind, harness, params, **_kwargs):
        sent.append({"kind": kind, "harness": harness, **params})
        return ("document", {"stdout": "{}", "exit_code": 0})

    monkeypatch.setattr(render, "native_render_cli", native_render_cli)
    monkeypatch.setattr(render.Path, "home", classmethod(lambda _cls: Path("/Users/alice")))
    answer = {"policy_action": "allow"}
    assert render.native_cli_hook_emit("codex", answer, event_name="Stop", guard_home=tmp_path, document=True) == {
        "stdout": "{}",
        "exit_code": 0,
    }
    render.native_cli_hook_emit("codex", answer, event_name="Stop", guard_home=tmp_path)

    def homeless(_cls):
        raise RuntimeError("Could not determine home directory")

    monkeypatch.setattr(render.Path, "home", classmethod(homeless))
    render.native_cli_hook_emit("codex", answer, event_name="Stop", document=True)
    assert sent[0]["kind"] == "cli_hook_emit"
    assert sent[0]["document"] is True
    assert sent[0]["home_dir"] == "/Users/alice"
    assert sent[0]["guard_home"] == str(tmp_path)
    assert "document" not in sent[1] and "home_dir" not in sent[1]
    assert sent[2]["document"] is True and "home_dir" not in sent[2]


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
    # The Cursor route sends the edge result the daemon already produced, which
    # the ordinary budget is too small to hold, so that kind asks for its own.
    assert render.native_render_cli("cursor_shell_route", "cursor", {}, guard_home=tmp_path) is None
    assert budgets == {
        "cli_hook_emit": render._CLI_HOOK_EMIT_MAX_REQUEST_BYTES,
        "cli_document": render._MAX_REQUEST_BYTES,
        "cursor_shell_route": render._CURSOR_ROUTE_MAX_REQUEST_BYTES,
    }


def test_a_spent_review_budget_still_delivers_the_decided_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    """The review owns the hook's budget and may use all of it.

    Writing the answer the review decided gets a floor of its own, so a verdict
    Guard already reached - an allow as readily as a block - is not thrown away
    for a fail-closed document by a clock the review already ran out.
    """

    seen: list[float | None] = []
    printed = '{\n  "policy_action": "allow"\n}'

    def rendered(harness, response, *, event_name, guard_home=None, deadline=None, document=False):
        del harness, response, event_name, guard_home, document
        seen.append(deadline)
        return {"stdout": printed, "exit_code": 0, "policy_action": "allow"}

    monkeypatch.setattr(cli, "native_cli_hook_emit", rendered)
    stream = io.StringIO()
    before = time.monotonic()
    code = cli.emit_hook_review(
        "cursor",
        {"policy_action": "allow"},
        event_name="PreToolUse",
        output_stream=stream,
        deadline=time.monotonic() - 5.0,
    )
    assert code == 0
    assert stream.getvalue() == printed + "\n"
    assert len(seen) == 1
    delivery = seen[0]
    assert delivery is not None
    assert delivery >= before + cli._DELIVERY_BUDGET_SECONDS


def test_delivery_leaves_a_deadline_with_budget_left_alone() -> None:
    deadline = time.monotonic() + 30.0
    assert cli._delivery_deadline(deadline) == deadline
    assert cli._delivery_deadline(None) is None
