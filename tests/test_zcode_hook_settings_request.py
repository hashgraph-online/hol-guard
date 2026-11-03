"""The requests the ZCode hook-settings shim sends the native runtime and how it checks the answers."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_runner_authority as native_module
from codex_plugin_scanner.guard.adapters import zcode
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.zcode import ZCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.zcode_config import ZCODE_PRETOOL_MATCHERS
from codex_plugin_scanner.guard.adapters.zcode_hook_settings import install_hook_surface, uninstall_hook_surface
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError

PATH = Path("/home/user/.zcode/cli/config.json")
LIVE = json.dumps({"present": True, "value": True})
Answer = Callable[[dict[str, object]], object]


class _Native:
    def __init__(self, answer: Answer) -> None:
        self.answer = answer
        self.sent: list[tuple[str, dict[str, object]]] = []

    def __call__(self, kind: str, args: dict[str, object], **_kwargs: object) -> object:
        self.sent.append((kind, dict(args)))
        return self.answer(args)


def _native(monkeypatch: pytest.MonkeyPatch, answer: object) -> _Native:
    def reply(args: dict[str, object]) -> object:
        if isinstance(answer, Exception):
            raise answer
        return answer(args) if callable(answer) else answer

    native = _Native(reply)
    monkeypatch.setattr(native_module, "native_runner_authority", native)
    return native


def _context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[HarnessContext, Path, Path, Path]:
    monkeypatch.delenv("ZCODE_HOME", raising=False)
    monkeypatch.setattr(zcode, "prepare_guard_shim", lambda *_a, **_k: SimpleNamespace(manifest={}, files=()))
    monkeypatch.setattr(ZCodeHarnessAdapter, "_hook_command_parts", staticmethod(lambda *_a, **_k: ("guard", "hook")))
    context = HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")
    cli = context.home_dir / ".zcode" / "cli"
    cli.mkdir(parents=True)
    state = context.guard_home / "managed" / "zcode" / "install.state.json"
    return context, cli / "config.json", cli / "setting.json", state


def _rendered(args: dict[str, object]) -> object:
    return {"text": f"new {Path(str(args['path'])).name}\n", "enabled": LIVE}


def test_install_sends_each_surface_and_keeps_the_rendered_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, config, setting, state = _context(tmp_path, monkeypatch)
    config.write_text('{"mcp": {}}', encoding="utf-8")
    setting.write_text("{oops", encoding="utf-8")
    state.parent.mkdir(parents=True)
    history = {str(config): {"present": True, "value": False}}
    state.write_text(json.dumps({"managed_config_path": "m", "hooks_enabled_before": history}), encoding="utf-8")
    native = _native(monkeypatch, _rendered)

    prepared = ZCodeHarnessAdapter().prepare_install(context)

    common = {
        "op": "install",
        "history": history,
        "managed_config_path": "m",
        "matchers": list(ZCODE_PRETOOL_MATCHERS),
        "command": "guard hook",
        "timeouts": {"PreToolUse": 30, "UserPromptSubmit": 30},
    }
    assert native.sent == [
        ("zcode_hook_settings", {**common, "text": '{"mcp": {}}', "path": str(config), "desktop": True}),
        ("zcode_hook_settings", {**common, "text": "{oops", "path": str(setting), "desktop": False}),
    ]
    after = {change.path: change.after for change in prepared.files}
    assert after[config.resolve()] == b"new config.json\n"
    assert after[setting.resolve()] == b"new setting.json\n"
    saved = json.loads(after[state.resolve()] or b"")
    assert saved["hooks_enabled_before"] == {str(config): json.loads(LIVE), str(setting): json.loads(LIVE)}


def test_install_sends_an_absent_config_as_null_and_skips_an_absent_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, config, setting, state = _context(tmp_path, monkeypatch)
    native = _native(monkeypatch, _rendered)

    prepared = ZCodeHarnessAdapter().prepare_install(context)

    assert [(args["text"], args["path"], args["history"]) for _kind, args in native.sent] == [(None, str(config), None)]
    saved = json.loads({change.path: change.after for change in prepared.files}[state.resolve()] or b"")
    # The CLI migration copies config.json into setting.json, Guard's opt-in included.
    assert saved["hooks_enabled_before"] == {str(config): json.loads(LIVE), str(setting): json.loads(LIVE)}


@pytest.mark.parametrize(
    ("refusal", "message"),
    [
        ("not_object", "ZCode config must be a JSON object: config.json"),
        ("hooks_disabled", "ZCode user hooks are disabled in config.json"),
    ],
)
def test_install_refusals_keep_their_messages(refusal: str, message: str, monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, {"refusal": refusal})
    with pytest.raises(ValueError, match=message):
        install_hook_surface("{}", path=PATH, desktop=True, state={}, command="g", timeouts={})


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {"text": "x"},
        {"text": "x", "enabled": LIVE, "more": 1},
        {"text": 1, "enabled": LIVE},
        {"text": "x", "enabled": {"present": True, "value": True}},
        {"text": "x", "enabled": "{not json"},
        {"text": "x", "enabled": "[]"},
        {"text": "x", "enabled": json.dumps({"present": 1, "value": True})},
        {"text": "x", "enabled": json.dumps({"present": True})},
        {"refusal": "unknown"},
        {"refusal": "not_object", "text": "x"},
    ],
)
def test_install_refuses_malformed_answers(answer: object, monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, answer)
    with pytest.raises(ValueError, match="answer is malformed"):
        install_hook_surface("{}", path=PATH, desktop=True, state={}, command="g", timeouts={})


@pytest.mark.parametrize("answer", [None, {}, {"text": 1}, {"text": None, "x": 1}, {"refusal": "not_object"}])
def test_uninstall_refuses_malformed_answers(answer: object, monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, answer)
    with pytest.raises(ValueError, match="answer is malformed"):
        uninstall_hook_surface("{}", path=PATH, state={})


def test_native_refusal_becomes_a_zcode_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _native(monkeypatch, NativeRunnerAuthorityError("native_runner_authority_invalid"))
    with pytest.raises(ValueError, match="ZCode hook settings plan failed"):
        uninstall_hook_surface("{}", path=PATH, state={})


def _managed_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[HarnessContext, Path, Path, Path]:
    context, config, setting, state = _context(tmp_path, monkeypatch)
    config.write_text('{"hooks": {"enabled": true}}', encoding="utf-8")
    setting.write_text('{"hooks": {}}', encoding="utf-8")
    state.parent.mkdir(parents=True)
    state.write_text(json.dumps({"managed_config_path": str(config)}), encoding="utf-8")
    return context, config, setting, state


def test_uninstall_writes_only_the_surfaces_that_changed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context, config, setting, state = _managed_install(tmp_path, monkeypatch)
    native = _native(monkeypatch, lambda args: {"text": "{}\n" if args["path"] == str(config) else None})
    monkeypatch.setattr(zcode, "remove_guard_shim", lambda *_a, **_k: {})

    ZCodeHarnessAdapter().uninstall(context)

    assert [args for _kind, args in native.sent] == [
        {
            "op": "uninstall",
            "text": '{"hooks": {}}',
            "path": str(setting),
            "history": None,
            "managed_config_path": str(config),
        },
        {
            "op": "uninstall",
            "text": '{"hooks": {"enabled": true}}',
            "path": str(config),
            "history": None,
            "managed_config_path": str(config),
        },
    ]
    assert config.read_text(encoding="utf-8") == "{}\n"
    assert setting.read_text(encoding="utf-8") == '{"hooks": {}}'
    assert not state.exists()


@pytest.mark.parametrize("answer", [NativeRunnerAuthorityError("native_runner_authority_invalid"), {"enabled": 1}])
def test_refused_uninstall_leaves_shim_files_and_state(
    answer: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context, config, setting, state = _managed_install(tmp_path, monkeypatch)
    before = config.read_bytes(), setting.read_bytes()
    _native(monkeypatch, answer)
    removed: list[str] = []
    monkeypatch.setattr(zcode, "remove_guard_shim", lambda harness, *_a, **_k: removed.append(harness))

    with pytest.raises(ValueError, match="ZCode hook settings"):
        ZCodeHarnessAdapter().uninstall(context)

    assert removed == []
    assert (config.read_bytes(), setting.read_bytes()) == before
    assert state.is_file()
