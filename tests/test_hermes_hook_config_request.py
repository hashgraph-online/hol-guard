"""Hermes hook ownership is answered by the native `hermes_hook_config` kind."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import hermes_runtime_hooks

_COMMAND = ["/usr/bin/python3", "-I", "/opt/guard/pretool-hook.py"]
_COMMAND_TEXT = "/usr/bin/python3 -I /opt/guard/pretool-hook.py"


def _fake(monkeypatch: pytest.MonkeyPatch, *answers: object) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []
    pending = list(answers)

    def fake_native(kind: str, request: dict[str, object], **_: object) -> object:
        assert kind == "hermes_hook_config"
        sent.append(json.loads(json.dumps(request)))
        return pending.pop(0)

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    return sent


def test_merge_keeps_the_answered_entries_and_appends_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"keep": [0], "removed": ["old"]})
    config: dict[str, object] = {"hooks": {"pre_tool_call": [{"command": "user"}, {"command": "old"}]}}

    merged, removed = hermes_runtime_hooks.merge_guard_pretool_hook(config, command=_COMMAND, timeout_seconds=9)

    assert (merged, removed) == (True, ["old"])
    assert sent[0]["op"] == "pretool_plan"
    assert sent[0]["expected_command"] == _COMMAND_TEXT
    assert Path(str(sent[0]["cwd"])).is_absolute()
    hooks = config["hooks"]
    assert isinstance(hooks, dict)
    assert hooks["pre_tool_call"] == [
        {"command": "user"},
        {"id": "hol-guard-pretool", "matcher": ".*", "command": _COMMAND_TEXT, "timeout": 9, "fail_closed": True},
    ]


def test_removing_every_entry_drops_the_hooks_section(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"keep": [], "removed": ["old"]})
    config: dict[str, object] = {"hooks": {"pre_tool_call": [{"command": "old"}]}}

    assert hermes_runtime_hooks.remove_guard_pretool_hooks(config) == ["old"]
    assert sent[0]["expected_command"] is None
    assert sent[0]["cwd"] is None
    assert config == {}


def test_registration_sends_unreadable_allowlist_as_false(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    allowlist = tmp_path / "shell-hooks-allowlist.json"
    allowlist.write_text("[]", encoding="utf-8")
    sent = _fake(monkeypatch, {"registered": False})
    config = {"hooks": {"pre_tool_call": [{"command": _COMMAND_TEXT}]}}

    assert hermes_runtime_hooks.guard_pretool_hook_registered(config, allowlist_path=allowlist) is False
    assert sent[0]["approvals"] is False


def test_only_the_matched_fields_are_sent_and_items_are_kept_whole(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    allowlist = tmp_path / "shell-hooks-allowlist.json"
    odd = {"event": "pre_tool_call", "command": "\ud800"}
    noted = {"event": "pre_tool_call", "command": "user", "note": "\ud800"}
    allowlist.write_text(json.dumps({"approvals": [odd, noted, 3]}), encoding="utf-8")
    sent = _fake(monkeypatch, {"keep": [0, 1], "append": True})

    hermes_runtime_hooks.merge_guard_hook_allowlist(tmp_path, command=_COMMAND)

    assert sent[0]["approvals"] == [{"event": "pre_tool_call"}, {"event": "pre_tool_call", "command": "user"}, None]
    written = json.loads(allowlist.read_text(encoding="utf-8"))
    assert written["approvals"] == [odd, noted, {"event": "pre_tool_call", "command": _COMMAND_TEXT}]


def test_registration_probe_fails_closed_when_the_resident_cannot_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(kind: str, request: dict[str, object], **_: object) -> object:
        raise authority.NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", unavailable)
    config = {"hooks": {"pre_tool_call": [{"command": _COMMAND_TEXT}]}}

    assert hermes_runtime_hooks.guard_pretool_hook_registered(config) is False


@pytest.mark.parametrize("answer", [{"keep": [0]}, {"keep": [0], "append": "yes"}])
def test_an_allowlist_plan_without_a_boolean_append_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: object
) -> None:
    (tmp_path / "shell-hooks-allowlist.json").write_text(json.dumps({"approvals": [{}]}), encoding="utf-8")
    _fake(monkeypatch, answer)

    with pytest.raises(authority.NativeRunnerAuthorityError, match="native_hermes_hook_config_invalid"):
        hermes_runtime_hooks.merge_guard_hook_allowlist(tmp_path, command=_COMMAND)


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"keep": [5], "removed": []},
        {"keep": [True], "removed": []},
        {"keep": [0], "removed": [1]},
        {"keep": [0, 0], "removed": []},
        {"keep": [1, 0], "removed": []},
    ],
)
def test_a_malformed_answer_fails_closed(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    _fake(monkeypatch, answer)
    config: dict[str, object] = {"hooks": {"pre_tool_call": [{"command": "user"}, {"command": "other"}]}}

    with pytest.raises(authority.NativeRunnerAuthorityError, match="native_hermes_hook_config_invalid"):
        hermes_runtime_hooks.remove_guard_pretool_hooks(config)
