"""The requests the Muse and Devin hook settings shim sends the native kind, and the answers it refuses."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runner_authority as authority
from codex_plugin_scanner.guard.adapters import harness_hook_settings as settings
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError

_USER = {"type": "command", "command": "echo user", "timeout": 3}
_STALE = {"type": "command", "command": "old # HOL_GUARD_MANAGED_MUSE"}
_STATUS = "HOL Guard is checking this action"


def _fake(monkeypatch: pytest.MonkeyPatch, *answers: dict[str, object]) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []
    queue = list(answers)

    def fake_native(kind: str, request: dict[str, object]) -> dict[str, object]:
        assert kind == "harness_hook_settings"
        sent.append(request)
        return queue.pop(0)

    monkeypatch.setattr(authority, "native_runner_authority", fake_native)
    return sent


def test_install_rebuilds_the_callers_objects_in_the_answered_order(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = {"matcher": "Bash", "hooks": [_STALE, _USER], "z": "é"}
    hooks: dict[str, object] = {"Notification": "x", "PreToolUse": ["kept", entry]}
    guard = {"timeout": 35, "status": _STATUS}
    answer = {
        "hooks": [
            ["Notification", None, None],
            ["PreToolUse", [0, {"entry": 1, "hooks": [1]}, {"matcher": None}], guard],
            ["Stop", [{"matcher": "雪"}], {"timeout": 30, "status": None}],
        ]
    }
    sent = _fake(monkeypatch, answer)

    rebuilt = settings.plan_guard_hooks("muse", hooks, 30).apply("guard hook")

    assert sent == [
        {
            "op": "install",
            "harness": "muse",
            "hooks": hooks,
            "hooks_keys": ["Notification", "PreToolUse"],
            "bridge_seconds": 30,
        }
    ]
    handler = {"type": "command", "command": "guard hook", "timeout": 35, "statusMessage": _STATUS}
    assert rebuilt == {
        "Notification": "x",
        "PreToolUse": ["kept", {"matcher": "Bash", "hooks": [_USER], "z": "é"}, {"hooks": [handler]}],
        "Stop": [{"hooks": [{"type": "command", "command": "guard hook", "timeout": 30}], "matcher": "雪"}],
    }
    pre_tool = rebuilt["PreToolUse"]
    assert isinstance(pre_tool, list)
    assert list(pre_tool[1]) == ["matcher", "hooks", "z"]
    assert pre_tool[1]["hooks"][0] is _USER


def test_devin_sends_the_approval_wait_and_no_keys_for_a_missing_hooks_value(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _fake(monkeypatch, {"hooks": []})

    assert settings.plan_guard_hooks("devin", None, 120).apply("x") == {}
    assert sent == [{"op": "install", "harness": "devin", "hooks": None, "hooks_keys": None, "wait_seconds": 120}]


@pytest.mark.parametrize(
    ("answer", "event"),
    [
        ({"error": "harness_hook_settings_hooks_not_object", "event": None}, None),
        ({"error": "harness_hook_settings_event_not_list", "event": "雪"}, "雪"),
    ],
)
def test_refusals_name_the_event(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object], event: str | None) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(settings.HookSettingsRefusedError) as refused:
        settings.plan_guard_hooks("muse", {"雪": "x"}, 30)
    assert refused.value.event == event
    assert isinstance(refused.value, ValueError)


def test_prune_keeps_untouched_events_and_drops_the_unanswered(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = {"hooks": [_STALE, _USER], "matcher": "Bash"}
    hooks: dict[str, object] = {"Custom": {}, "PreToolUse": [entry], "Stop": [{"hooks": [_STALE]}]}
    sent = _fake(monkeypatch, {"hooks": [["Custom", None], ["PreToolUse", [{"entry": 0, "hooks": [1]}]]]})

    pruned = settings.prune_guard_hooks("devin", hooks)

    assert sent == [{"op": "prune", "harness": "devin", "hooks": hooks, "hooks_keys": ["Custom", "PreToolUse", "Stop"]}]
    assert pruned == {"Custom": {}, "PreToolUse": [{"hooks": [_USER], "matcher": "Bash"}]}
    assert pruned["Custom"] is hooks["Custom"]


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"hooks": [], "extra": 1},
        {"hooks": "x"},
        {"hooks": [["Stop", [0]]]},
        {"hooks": [["Stop", None, None], ["Stop", None, None]]},
        {"hooks": [[7, None, None]]},
        {"hooks": [["Stop", [5], None]]},
        {"hooks": [["Stop", [True], None]]},
        {"hooks": [["Stop", None, {"timeout": 30, "status": None}]]},
        {"hooks": [["Gone", None, None]]},
        {"hooks": [["Stop", [{"matcher": None}], None]]},
        {"hooks": [["Stop", [{"entry": 0, "hooks": [None]}], None]]},
        {"hooks": [["Stop", [{"entry": 0, "hooks": [], "x": 1}], None]]},
        {"hooks": [["Stop", [{"matcher": 5}], {"timeout": 30, "status": None}]]},
        {"hooks": [["Stop", [], {"timeout": True, "status": None}]]},
        {"hooks": [["Stop", [], {"timeout": 30}]]},
        {"hooks": [["Stop", [], {"timeout": 30, "status": 5}]]},
        {"error": "other", "event": None},
        {"error": "harness_hook_settings_event_not_list", "event": None},
        {"error": "harness_hook_settings_hooks_not_object", "event": None, "extra": 1},
    ],
)
def test_malformed_install_answers_are_refused(monkeypatch: pytest.MonkeyPatch, answer: dict[str, object]) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(NativeRunnerAuthorityError):
        settings.plan_guard_hooks("muse", {"Stop": [{"hooks": [_USER]}]}, 30)


@pytest.mark.parametrize(
    "call",
    [
        lambda: settings.prune_guard_hooks("muse", {"Stop": []}),
        lambda: settings.plan_guard_hooks("devin", {}, 0),
    ],
)
@pytest.mark.parametrize(
    "answer",
    [
        {"hooks": [["Stop", None, None, None]]},
        {"hooks": [["Gone", None]]},
        {"error": "harness_hook_settings_hooks_not_object", "event": None, "hooks": []},
    ],
)
def test_malformed_answers_are_refused(
    monkeypatch: pytest.MonkeyPatch, call: Callable[[], object], answer: dict[str, object]
) -> None:
    _fake(monkeypatch, answer)

    with pytest.raises(NativeRunnerAuthorityError):
        call()


def test_a_prune_refusal_is_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake(monkeypatch, {"error": "harness_hook_settings_hooks_not_object", "event": None})

    with pytest.raises(NativeRunnerAuthorityError):
        settings.prune_guard_hooks("muse", {})


@pytest.mark.parametrize("adapter_name", ["muse", "devin"])
def test_a_refused_uninstall_prune_leaves_the_launcher_and_settings(
    adapter_name: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard.adapters import devin, muse
    from codex_plugin_scanner.guard.adapters.base import HarnessContext

    module = muse if adapter_name == "muse" else devin
    adapter = muse.MuseHarnessAdapter() if adapter_name == "muse" else devin.DevinHarnessAdapter()
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    config = adapter._user_settings_path(context) if adapter_name == "muse" else adapter._user_config_path(context)  # pyright: ignore[reportPrivateUsage, reportAttributeAccessIssue]
    config.parent.mkdir(parents=True)
    original = json.dumps({"hooks": {"PreToolUse": [{"hooks": [_USER]}]}})
    config.write_text(original, encoding="utf-8")
    removed: list[str] = []
    monkeypatch.setattr(module, "remove_guard_shim", lambda *_args, **_kwargs: removed.append("shim"))

    def refuse(_kind: str, _request: dict[str, object]) -> dict[str, object]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(authority, "native_runner_authority", refuse)
    with pytest.raises(NativeRunnerAuthorityError):
        adapter.uninstall(context)
    assert removed == []
    assert config.read_text(encoding="utf-8") == original
