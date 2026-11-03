"""Kimi's managed hooks block in ``config.toml`` is composed by the native runtime."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

from codex_plugin_scanner.guard import native_runner_authority as native_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.kimi import KimiHarnessAdapter, _managed_config_text

_VECTORS = (
    Path(__file__).resolve().parents[1]
    / "rust"
    / "crates"
    / "guard-runtime"
    / "testdata"
    / "kimi"
    / "hook_config_vectors.json"
)


def _native(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[object]:
    original = native_module.native_runner_authority
    calls: list[object] = []

    def native(kind: str, request: Any) -> object:
        if kind != "kimi_hook_config":
            return original(kind, request)
        calls.append(request)
        return answer

    monkeypatch.setattr("codex_plugin_scanner.guard.native_runner_authority.native_runner_authority", native)
    return calls


def _ctx(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")


def test_uninstall_writes_the_native_text(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    config = ctx.home_dir / ".kimi-code" / "config.toml"
    config.parent.mkdir()
    config.write_text("keep = 1\n# BEGIN HOL GUARD MANAGED HOOKS\n", encoding="utf-8")
    calls = _native(monkeypatch, {"text": "keep = 1\n"})
    KimiHarnessAdapter().uninstall(ctx)
    assert calls == [{"op": "uninstall", "text": "keep = 1\n# BEGIN HOL GUARD MANAGED HOOKS\n"}]
    assert config.read_text(encoding="utf-8") == "keep = 1\n"


def test_a_refused_uninstall_answer_keeps_the_launcher(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    config = ctx.home_dir / ".kimi-code" / "config.toml"
    config.parent.mkdir()
    config.write_text("keep = 1\n# BEGIN HOL GUARD MANAGED HOOKS\n", encoding="utf-8")
    _native(monkeypatch, {"text": 1})
    removed: list[str] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.kimi.remove_guard_shim",
        lambda harness, *_args, **_kwargs: removed.append(harness) or {},
    )
    with pytest.raises(ValueError, match="malformed"):
        KimiHarnessAdapter().uninstall(ctx)
    assert removed == []
    assert config.read_text(encoding="utf-8") == "keep = 1\n# BEGIN HOL GUARD MANAGED HOOKS\n"


def test_uninstall_without_a_config_asks_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = _native(monkeypatch, {"text": "unused"})
    KimiHarnessAdapter().uninstall(_ctx(tmp_path))
    assert calls == []


@pytest.mark.parametrize("answer", [{}, {"text": 1}, {"text": "x", "extra": 1}, ["x"], None])
def test_a_malformed_answer_is_refused(monkeypatch: pytest.MonkeyPatch, answer: object) -> None:
    _native(monkeypatch, answer)
    with pytest.raises(ValueError, match="malformed"):
        _managed_config_text({"op": "uninstall", "text": "x"})


def test_every_recorded_request_is_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    for case in json.loads(_VECTORS.read_text(encoding="utf-8"))["cases"]:
        calls = _native(monkeypatch, {"text": case["text"]})
        assert _managed_config_text(case["request"]) == case["text"]
        assert calls == [case["request"]], case["name"]


def test_recorded_install_blocks_parse_and_keep_the_command() -> None:
    for case in json.loads(_VECTORS.read_text(encoding="utf-8"))["cases"]:
        request = case["request"]
        if request["op"] != "install" or not case["name"].startswith("install-user-hooks-"):
            continue
        hooks = tomllib.loads(case["text"])["hooks"]
        assert [hook["event"] for hook in hooks] == [
            "PostToolUse",
            "PreToolUse",
            "UserPromptSubmit",
            "PostToolUse",
            "SessionStart",
            "Stop",
        ], case["name"]
        assert {hook["command"] for hook in hooks[1:]} == {request["hook_command"]}, case["name"]
