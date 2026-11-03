"""The requests the ZCode hook-settings shim sends the native runtime and how it checks the answers."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_runner_authority as native_module
from codex_plugin_scanner.guard.adapters import zcode
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.zcode_config import GUARD_MANAGED_MARKER, ZCODE_PRETOOL_MATCHERS
from codex_plugin_scanner.guard.adapters.zcode_hook_settings import plan_hook_settings
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError

PATH = Path("/home/user/.zcode/cli/config.json")
GUARD = f"guard-hook # {GUARD_MANAGED_MARKER}"
HANDLERS: dict[str, dict[str, object]] = {
    "PreToolUse": {"type": "command", "command": GUARD, "timeout": 30},
    "UserPromptSubmit": {"type": "command", "command": GUARD, "timeout": 30},
}


class _Native:
    def __init__(self, answer: object) -> None:
        self.answer = answer
        self.sent: list[tuple[str, dict[str, object]]] = []

    def __call__(self, kind: str, args: dict[str, object], **_kwargs: object) -> object:
        self.sent.append((kind, dict(args)))
        if isinstance(self.answer, Exception):
            raise self.answer
        return copy.deepcopy(self.answer)


def _native(monkeypatch: pytest.MonkeyPatch, answer: object) -> _Native:
    native = _Native(answer)
    monkeypatch.setattr(native_module, "native_runner_authority", native)
    return native


def _hooks() -> dict[str, object]:
    return {
        "enabled": True,
        "PreToolUse": [{"matcher": "Bash", "hooks": [{"command": "echo legacy"}]}],
        "events": {
            "PreToolUse": [{"matcher": "Read", "hooks": [{"command": "echo read"}, {"command": GUARD}]}],
            "Stop": [{"hooks": [{"command": "echo stop"}]}],
        },
    }


INSTALL: dict[str, object] = {
    "enabled": None,
    "has_handlers": True,
    "drop": ["PreToolUse"],
    "events": [
        [
            "PreToolUse",
            [
                {"copy": ["events", 0], "hooks": [0, "guard"]},
                {"copy": ["hooks", 0], "hooks": [0, "guard"]},
                {"group": "Write"},
            ],
        ],
        ["UserPromptSubmit", [{"group": None}]],
    ],
}
UNINSTALL: dict[str, object] = {
    "enabled": None,
    "events": [["PreToolUse", [{"copy": ["events", 0], "hooks": [0]}]], ["Stop", [["events", 0]]]],
    "hooks": [["PreToolUse", None]],
}


def test_install_request_carries_ordered_hooks_text_and_matchers(monkeypatch: pytest.MonkeyPatch) -> None:
    native = _native(monkeypatch, INSTALL)
    hooks = _hooks()
    state = {"hooks_enabled_before": {str(PATH): {"present": False, "value": None}}, "managed_config_path": "x"}

    plan_hook_settings("install", hooks, path=PATH, state=state, handlers=HANDLERS)

    assert native.sent == [
        (
            "zcode_hook_settings",
            {
                "op": "install",
                "hooks": json.dumps(hooks, ensure_ascii=False),
                "path": str(PATH),
                "history": state["hooks_enabled_before"],
                "managed_config_path": "x",
                "matchers": list(ZCODE_PRETOOL_MATCHERS),
            },
        )
    ]


def test_uninstall_request_has_no_matchers(monkeypatch: pytest.MonkeyPatch) -> None:
    native = _native(monkeypatch, UNINSTALL)
    plan_hook_settings("uninstall", _hooks(), path=PATH, state={})
    assert native.sent[0][0] == "zcode_hook_settings"
    assert set(native.sent[0][1]) == {"op", "hooks", "path", "history", "managed_config_path"}
    assert native.sent[0][1]["op"] == "uninstall"


def test_install_plan_keeps_the_callers_own_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, INSTALL)
    hooks = _hooks()
    events = hooks["events"]
    assert isinstance(events, dict)
    stop, legacy = events["Stop"], hooks["PreToolUse"]
    plan = plan_hook_settings("install", hooks, path=PATH, state={}, handlers=HANDLERS)
    plan.apply(hooks)

    assert plan.enabled == {"present": True, "value": True}
    assert plan.has_handlers is True
    assert list(hooks) == ["enabled", "events"]
    after = hooks["events"]
    assert isinstance(after, dict)
    assert list(after) == ["PreToolUse", "Stop", "UserPromptSubmit"]
    assert after["Stop"] is stop
    assert after["PreToolUse"] == [
        {"matcher": "Read", "hooks": [{"command": "echo read"}, HANDLERS["PreToolUse"]]},
        {"matcher": "Bash", "hooks": [{"command": "echo legacy"}, HANDLERS["PreToolUse"]]},
        {"hooks": [HANDLERS["PreToolUse"]], "matcher": "Write"},
    ]
    assert isinstance(legacy, list)
    assert after["PreToolUse"][1]["hooks"][0] is legacy[0]["hooks"][0]
    assert after["UserPromptSubmit"] == [{"hooks": [HANDLERS["UserPromptSubmit"]]}]


def test_uninstall_plan_prunes_and_drops_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, UNINSTALL)
    hooks = _hooks()
    plan_hook_settings("uninstall", hooks, path=PATH, state={}).apply(hooks)
    assert hooks == {
        "enabled": True,
        "events": {
            "PreToolUse": [{"matcher": "Read", "hooks": [{"command": "echo read"}]}],
            "Stop": [{"hooks": [{"command": "echo stop"}]}],
        },
    }


def test_enabled_record_is_the_saved_one_or_the_live_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    for answer, expected in (
        ({"present": True, "value": False}, {"present": True, "value": False}),
        ({"present": False, "value": None}, {"present": False, "value": None}),
        (None, {"present": True, "value": True}),
    ):
        _native(monkeypatch, {**UNINSTALL, "enabled": answer})
        assert plan_hook_settings("uninstall", _hooks(), path=PATH, state={}).enabled == expected


def _variant(base: dict[str, object], path: tuple[str | int, ...], value: object) -> dict[str, object]:
    answer = copy.deepcopy(base)
    target: Any = answer
    for step in path[:-1]:
        target = target[step]
    if value is _DELETE:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return answer


_DELETE = object()
_PTU = ("events", 0, 1)
BAD_INSTALL: dict[str, tuple[tuple[str | int, ...], object]] = {
    "extra_key": (("surprise",), True),
    "missing_key": (("drop",), _DELETE),
    "has_handlers_not_bool": (("has_handlers",), "yes"),
    "drop_not_a_list_key": (("drop",), ["enabled"]),
    "drop_repeated": (("drop",), ["PreToolUse", "PreToolUse"]),
    "events_wrong_order": (("events",), [["UserPromptSubmit", [{"group": None}]], ["PreToolUse", []]]),
    "events_extra": (("events",), [*cast(list[object], INSTALL["events"]), ["Stop", []]]),
    "index_out_of_range": ((*_PTU, 0, "copy", 1), 5),
    "index_bool": ((*_PTU, 0, "copy", 1), True),
    "unknown_source": ((*_PTU, 0, "copy", 0), "other"),
    "group_unknown_matcher": ((*_PTU, 2), {"group": "Nope"}),
    "group_extra_key": ((*_PTU, 2), {"group": "Write", "x": 1}),
    "handler_out_of_range": ((*_PTU, 0, "hooks"), [2]),
    "handler_unknown_word": ((*_PTU, 0, "hooks"), ["user"]),
    "plan_not_a_list": ((*_PTU,), None),
    "enabled_not_a_record": (("enabled",), True),
    "enabled_extra_key": (("enabled",), {"present": True, "value": True, "source": "live"}),
    "enabled_present_not_bool": (("enabled",), {"present": 1, "value": True}),
    "enabled_value_not_bool": (("enabled",), {"present": True, "value": "yes"}),
}


@pytest.mark.parametrize("name", sorted(BAD_INSTALL))
def test_install_refuses_malformed_answers(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    path, value = BAD_INSTALL[name]
    _native(monkeypatch, _variant(INSTALL, path, value))
    hooks = _hooks()
    before = json.dumps(hooks)
    with pytest.raises(ValueError, match="answer is malformed"):
        plan_hook_settings("install", hooks, path=PATH, state={}, handlers=HANDLERS)
    assert json.dumps(hooks) == before


def test_install_refuses_a_flat_reference_outside_the_dropped_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, _variant(INSTALL, ("drop",), []))
    with pytest.raises(ValueError, match="answer is malformed"):
        plan_hook_settings("install", _hooks(), path=PATH, state={}, handlers=HANDLERS)


BAD_UNINSTALL: dict[str, tuple[tuple[str | int, ...], object]] = {
    "has_install_keys": (("drop",), []),
    "names_mismatch": (("events",), [["Stop", [["events", 0]]]]),
    "empty_list_not_null": (("events", 1, 1), []),
    "guard_handler": (("events", 0, 1, 0, "hooks"), [0, "guard"]),
    "group": (("events", 1, 1), [{"group": None}]),
    "flat_refers_events": (("hooks", 0, 1), [["events", 0]]),
    "events_refers_flat": (("events", 1, 1), [["hooks", 0]]),
    "flat_names_mismatch": (("hooks",), []),
}


@pytest.mark.parametrize("name", sorted(BAD_UNINSTALL))
def test_uninstall_refuses_malformed_answers(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    path, value = BAD_UNINSTALL[name]
    _native(monkeypatch, _variant(UNINSTALL, path, value))
    with pytest.raises(ValueError, match="answer is malformed"):
        plan_hook_settings("uninstall", _hooks(), path=PATH, state={})


def test_native_refusal_becomes_a_zcode_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, NativeRunnerAuthorityError("native_runner_authority_invalid"))
    with pytest.raises(ValueError, match="ZCode hook settings plan failed"):
        plan_hook_settings("uninstall", _hooks(), path=PATH, state={})


def _managed_install(tmp_path: Path) -> tuple[HarnessContext, Path, Path, bytes]:
    ctx = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    config = ctx.home_dir / ".zcode" / "cli" / "config.json"
    config.parent.mkdir(parents=True)
    hooks = {"enabled": True, "events": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"command": GUARD}]}]}}
    config.write_text(json.dumps({"hooks": hooks}, indent=2), encoding="utf-8")
    state = ctx.guard_home / "managed" / "zcode" / "install.state.json"
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"managed_config_path": str(config)}), encoding="utf-8")
    return ctx, config, state, config.read_bytes()


@pytest.mark.parametrize("answer", [NativeRunnerAuthorityError("native_runner_authority_invalid"), {"enabled": 1}])
def test_refused_uninstall_plan_leaves_shim_files_and_state(
    answer: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx, config, state, before = _managed_install(tmp_path)
    native = _native(monkeypatch, answer)
    removed: list[str] = []
    monkeypatch.setattr(zcode, "remove_guard_shim", lambda harness, *_args, **_kwargs: removed.append(harness))

    with pytest.raises(ValueError, match="ZCode hook settings"):
        ZCodeHarnessAdapter().uninstall(ctx)

    assert [kind for kind, _args in native.sent] == ["zcode_hook_settings"]
    assert removed == []
    assert config.read_bytes() == before
    assert state.is_file()


def test_refused_install_plan_leaves_config_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, config, _state, before = _managed_install(tmp_path)
    native = _native(monkeypatch, NativeRunnerAuthorityError("native_runner_authority_invalid"))

    with pytest.raises(ValueError, match="ZCode hook settings plan failed"):
        ZCodeHarnessAdapter().prepare_install(ctx)

    assert [kind for kind, _args in native.sent] == ["zcode_hook_settings"]
    assert config.read_bytes() == before
