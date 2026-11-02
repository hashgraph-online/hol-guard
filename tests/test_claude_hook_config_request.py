"""The requests the Claude hook config shims send the native kind, and the answers they refuse."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import claude_hook_config as config
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError

_GUARD = {"type": "command", "command": "guard", "args": ["hook"]}
_USER = {"type": "command", "command": "user-hook", "timeout": 3}


def _fake(monkeypatch: pytest.MonkeyPatch, *answers: dict[str, object]) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []
    queue = list(answers)

    def fake_native(kind: str, request: dict[str, object]) -> dict[str, object]:
        assert kind == "claude_hook_config"
        sent.append(request)
        return queue.pop(0)

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    return sent


def test_text_questions_skip_non_strings(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"command": True, "url": False}, {"command": False, "url": True})

    assert config.is_guard_hook_command("guard hook") is True
    assert config.is_guard_hook_url("http://127.0.0.1:1/v1/hooks/claude-code") is True
    assert config.is_guard_hook_command(None) is False
    assert config.is_guard_hook_url(7) is False
    assert sent == [
        {"op": "text", "value": "guard hook"},
        {"op": "text", "value": "http://127.0.0.1:1/v1/hooks/claude-code"},
    ]


def test_handler_answers_become_tuples_and_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = {"guard": True, "argv": ["guard", "hook"], "identity": ["command", "exec", "guard", "hook"]}
    sent = _fake(monkeypatch, answer, answer, answer, {"guard": None, "argv": None, "identity": ["x"]})

    assert config.command_handler_argv(_GUARD) == ("guard", "hook")
    assert config.handler_identity(_GUARD) == ("command", "exec", "guard", "hook")
    assert config.is_guard_hook_handler(_GUARD) is True
    assert config.is_guard_hook_handler("not a handler") is False
    with pytest.raises(TypeError):
        config.is_guard_hook_handler({"type": ["command"]})
    assert sent[0] == {"op": "handler", "handler": _GUARD}


def test_prune_rebuilds_the_callers_objects_in_their_key_order(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = {"matcher": "Bash", "hooks": [_GUARD, _USER], "z": 1}
    entries: list[object] = ["kept", entry, {"hooks": [_GUARD]}]
    sent = _fake(monkeypatch, {"lists": [[0, {"entry": 1, "hooks": [1]}]]})

    pruned = config.prune_guard_hook_entries(entries)

    assert sent == [{"op": "prune", "lists": [entries]}]
    assert pruned == ["kept", {"matcher": "Bash", "hooks": [_USER], "z": 1}]
    assert list(pruned[1]) == ["matcher", "hooks", "z"]
    assert pruned[1]["hooks"][0] is _USER


def test_merge_sends_one_job_and_places_the_guard_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    entries: list[object] = [{"hooks": [_USER], "matcher": "Bash"}]
    sent = _fake(monkeypatch, {"jobs": [[{"entry": 0, "hooks": [0, None]}, {"matcher": "Read"}]]})

    merged = config.merge_hook_group(entries, "Bash", _GUARD)

    assert sent == [
        {"op": "merge", "jobs": [{"entries": entries, "prune": False, "matchers": ["Bash"], "handler": _GUARD}]}
    ]
    assert merged == [{"hooks": [_USER, _GUARD], "matcher": "Bash"}, {"hooks": [_GUARD], "matcher": "Read"}]
    assert merged[0]["hooks"][1] is _GUARD


def test_sync_batches_every_runtime_group_in_one_request(monkeypatch: pytest.MonkeyPatch) -> None:
    groups = config.CLAUDE_RUNTIME_HOOK_GROUPS
    sent = _fake(monkeypatch, {"jobs": [[{"matcher": group.matcher}] for group in groups]})
    hooks: dict[str, object] = {"PreToolUse": [{"hooks": [_USER]}], "Stop": "not a list"}

    config.sync_runtime_hook_groups(hooks, ("guard", "hook"))

    (request,) = sent
    jobs = request["jobs"]
    assert isinstance(jobs, list)
    assert [job["entries"] for job in jobs] == [
        [{"hooks": [_USER]}] if group.event == "PreToolUse" else [] for group in groups
    ]
    assert {job["prune"] for job in jobs} == {True}
    assert [job["matchers"] for job in jobs] == [[group.matcher] for group in groups]
    assert list(hooks) == [
        "PreToolUse",
        "Stop",
        *(group.event for group in groups if group.event not in {"PreToolUse", "Stop"}),
    ]


def test_retired_events_are_popped_when_nothing_remains(monkeypatch: pytest.MonkeyPatch) -> None:
    (event,) = config.CLAUDE_GUARD_PRUNED_HOOK_EVENTS
    sent = _fake(monkeypatch, {"lists": [[]]})
    hooks: dict[str, object] = {event: [{"hooks": [_GUARD]}]}

    config.remove_unsupported_guard_hook_groups(hooks)
    config.remove_unsupported_guard_hook_groups({event: "not a list"})

    assert sent == [{"op": "prune", "lists": [[{"hooks": [_GUARD]}]]}]
    assert hooks == {}


def test_missing_sends_only_the_hooks_and_the_required_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"missing": ["PermissionRequest"]})
    diagnostics: dict[str, object] = {"setup_status": "active"}

    config.mark_missing_guard_hooks(diagnostics, "settings.json", {"hooks": {}, "model": "x"})

    assert sent == [
        {
            "op": "missing",
            "payload": {"hooks": {}},
            "events": list(config.CLAUDE_GUARD_REQUIRED_HOOK_EVENTS),
            "matcher": config.CLAUDE_GUARD_TOOL_MATCHER,
        }
    ]
    assert diagnostics["setup_status"] == "broken"


def test_the_unhashable_answer_raises_type_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, {"error": "claude_hook_handler_type_unhashable"})

    with pytest.raises(TypeError):
        config.prune_guard_hook_entries([{"hooks": [{"type": {}}]}])


@pytest.mark.parametrize(
    "answer",
    [
        {"error": "other"},
        {"lists": []},
        {"lists": [[1]]},
        {"lists": [[True]]},
        {"lists": [[{"entry": 0, "hooks": [None]}]]},
        {"lists": [[{"entry": 0, "hooks": [5]}]]},
        {"lists": [[{"entry": 1, "hooks": []}]]},
        {"lists": [[{"matcher": "Bash"}]]},
        {"lists": [[{"entry": 0, "hooks": [], "extra": 1}]]},
        {"lists": ["not a plan"]},
    ],
)
def test_malformed_list_answers_are_refused(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(NativeRunnerAuthorityError):
        config.prune_guard_hook_entries([{"hooks": [_USER]}])


@pytest.mark.parametrize(
    ("call", "answer"),
    [
        (lambda: config.is_guard_hook_command("x"), {"command": 1, "url": False}),
        (lambda: config.is_guard_hook_handler({}), {"guard": "yes", "argv": None, "identity": [""]}),
        (lambda: config.command_handler_argv({}), {"guard": False, "argv": [1], "identity": [""]}),
        (lambda: config.handler_identity({}), {"guard": False, "argv": None, "identity": None}),
        (lambda: config.missing_guard_hook_events({}), {"missing": None}),
        (lambda: config.merge_hook_group([], None, _GUARD), {"jobs": [[{"matcher": 5}]]}),
    ],
)
def test_malformed_answers_are_refused(
    monkeypatch: pytest.MonkeyPatch, call: Callable[[], object], answer: dict[str, object]
) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(NativeRunnerAuthorityError):
        call()
