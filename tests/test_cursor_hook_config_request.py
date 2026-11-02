"""The requests the Cursor hook config shims send the native kind, and the answers they refuse."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import cursor_hook_config as config
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError

_SCRIPT = Path("/var/guard-user/.cursor/hooks/hol-guard-cursor-hook.py")


def _fake(monkeypatch: pytest.MonkeyPatch, *answers: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    sent: list[tuple[str, dict[str, object]]] = []
    queue = list(answers)

    def fake_native(kind: str, request: dict[str, object]) -> dict[str, object]:
        sent.append((kind, request))
        return queue.pop(0)

    monkeypatch.setattr(config, "native_runner_authority", fake_native)
    monkeypatch.setattr(config.codex_hook_command_line, "hook_commands_use_windows_syntax", lambda: False)
    return sent


def test_a_command_question_names_the_op_and_host_syntax(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"managed": True, "structured": True, "script": str(_SCRIPT), "short_tokens": []})

    assert config._is_managed_hook_command("python3 -I hook.py") is True
    assert config._is_managed_hook_command(7) is False
    assert sent == [
        (
            "cursor_hook_config",
            {"op": "command", "windows": False, "long_paths": {}, "command": "python3 -I hook.py"},
        )
    ]


def test_a_reported_short_name_is_resolved_and_asked_once_more(monkeypatch: pytest.MonkeyPatch) -> None:
    short = "C:\\Users\\GUARD-~1\\HOL-GU~1.PY"
    long = "C:\\Users\\guard-user\\.cursor\\hooks\\hol-guard-cursor-hook.py"
    first = {"managed": True, "structured": False, "script": None, "short_tokens": [short, "C:\\NONE~1"]}
    second = {"managed": True, "structured": True, "script": long, "short_tokens": [short, "C:\\NONE~1"]}
    sent = _fake(monkeypatch, first, second)
    monkeypatch.setattr(
        config.codex_hook_command_line, "_expand_short_token", lambda token: long if token == short else token
    )

    assert config._is_structured_managed_cursor_hook_command(f"py {short}") is True
    assert [request["long_paths"] for _kind, request in sent] == [{}, {short: long}]


def test_strip_sends_the_resolved_script_and_keeps_unmanaged_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"managed": [True, False], "short_tokens": []})
    entries: list[object] = [{"command": "guard"}, {"command": "other"}]

    assert config._strip_managed_hook_entries(entries, script_path=_SCRIPT) == [{"command": "other"}]
    assert config._strip_managed_hook_entries({"command": "x"}, script_path=_SCRIPT) == []
    assert sent[0][1] == {
        "op": "entries",
        "windows": False,
        "long_paths": {},
        "entries": entries,
        "command": str(_SCRIPT.resolve()),
    }


def test_install_rebuilds_user_json_in_the_native_order(monkeypatch: pytest.MonkeyPatch) -> None:
    foreign = {"command": "other-tool", "nested": {"z": 1, "a": 2}}
    payload: dict[str, object] = {"hooks": {"stop": [foreign, {"command": "old guard"}], "zz": "keep"}, "version": 2}
    managed: dict[str, dict[str, object]] = {"beforeShellExecution": {"command": "guard"}}
    sent = _fake(
        monkeypatch,
        {
            "version": 2,
            "hooks": [["stop", [0], False], ["zz", None, False], ["beforeShellExecution", [], True]],
            "short_tokens": [],
        },
    )

    result = config._managed_hooks_payload(payload, managed, script_path=_SCRIPT)

    assert result == {
        "version": 2,
        "hooks": {"stop": [foreign], "zz": "keep", "beforeShellExecution": [{"command": "guard"}]},
    }
    assert list(result["hooks"]) == ["stop", "zz", "beforeShellExecution"]  # type: ignore[arg-type]
    assert sent[0][1] == {
        "op": "install",
        "windows": False,
        "long_paths": {},
        "payload": payload,
        "top_keys": ["hooks", "version"],
        "hooks_keys": ["stop", "zz"],
        "managed": [["beforeShellExecution", "guard"]],
        "script": str(_SCRIPT.resolve()),
    }


def test_install_surfaces_the_unsupported_event_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, {"error": "guard_cursor_hook_unsupported_events:beforeWriteFile", "short_tokens": []})

    with pytest.raises(RuntimeError, match="guard_cursor_hook_unsupported_events:beforeWriteFile"):
        config._managed_hooks_payload({"beforeWriteFile": [{}]}, {}, script_path=_SCRIPT)


@pytest.mark.parametrize(
    "answer",
    [
        {"version": True, "hooks": [], "short_tokens": None},
        {"version": "1", "hooks": [], "short_tokens": []},
        {"version": 1, "hooks": [["stop", [5], False]], "short_tokens": []},
        {"version": 1, "hooks": [["stop", [True], False]], "short_tokens": []},
        {"version": 1, "hooks": [["stop", None, False]], "short_tokens": []},
        {"version": 1, "hooks": [["zz", None, True]], "short_tokens": []},
        {"version": 1, "hooks": [["stop", [], True]], "short_tokens": []},
        {"version": 1, "hooks": [["stop", [0], False], ["stop", [0], False]], "short_tokens": []},
        {"version": 1, "hooks": [["stop", [0]]], "short_tokens": []},
    ],
)
def test_malformed_install_answers_are_refused(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> None:
    _fake(monkeypatch, answer)
    payload: dict[str, object] = {"hooks": {"stop": [{"command": "x"}], "zz": "keep"}}

    with pytest.raises(NativeRunnerAuthorityError):
        config._managed_hooks_payload(payload, {}, script_path=_SCRIPT)


@pytest.mark.parametrize(
    ("call", "answer"),
    [
        (lambda: config._is_managed_hook_command("x"), {"managed": 1, "structured": False, "script": None}),
        (lambda: config._live_cursor_hook_script_path("x"), {"managed": True, "structured": True, "script": 3}),
        (lambda: config._is_managed_hook_entry({}, command="x"), {"managed": [True, False]}),
        (lambda: config._is_managed_hook_script("source"), {"managed": "yes"}),
        (lambda: config.managed_cursor_hook_commands({"stop": []}), {"commands": [{"command": "x"}]}),
        (lambda: config.managed_cursor_hook_commands({"stop": []}), {"commands": None}),
        (lambda: config.live_guard_cursor_hooks_intercept({"stop": []}), {"events": [["stop", []]]}),
        (lambda: config.live_guard_cursor_hooks_intercept({"stop": []}), {"events": "all"}),
    ],
)
def test_malformed_query_answers_are_refused(
    monkeypatch: pytest.MonkeyPatch, call: object, answer: dict[str, object]
) -> None:
    _fake(monkeypatch, {**answer, "short_tokens": []})

    with pytest.raises(NativeRunnerAuthorityError):
        call()  # type: ignore[operator]


def test_live_commands_keep_only_accepted_scripts_on_disk(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    script = tmp_path / ".cursor" / "hooks" / "hol-guard-cursor-hook.py"
    script.parent.mkdir(parents=True)
    script.write_text("# hook\n", encoding="utf-8")
    found = [
        {"command": "live", "script": str(script), "frozen": True},
        {"command": "gone", "script": str(tmp_path / "gone" / ".cursor" / "hooks" / script.name), "frozen": False},
        {"command": "elsewhere", "script": str(tmp_path / "hol-guard-cursor-hook.py"), "frozen": False},
    ]
    sent = _fake(monkeypatch, {"commands": found, "short_tokens": []}, {"commands": found, "short_tokens": []})

    assert config.managed_cursor_hook_commands({"stop": [{"command": "live"}]}) == ("live",)
    assert config.live_cursor_hooks_use_frozen_control_plane({"stop": []}) is True
    assert sent[0][1]["hooks"] == [["stop", [{"command": "live"}]]]
    assert config.managed_cursor_hook_commands("not a dict") == ()
