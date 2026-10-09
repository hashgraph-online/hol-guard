"""Pager values every hook sender reports as no wider than Git's default pager."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _render_bounded_hook_script
from codex_plugin_scanner.guard.hook_execution_environment import (
    HOOK_EXECUTION_ENVIRONMENT_KEY,
    pager_default_equivalent,
    stamp_hook_input_text,
)

FROZEN_ENTRYPOINT = Path(__file__).resolve().parents[1] / "scripts" / "mdm" / "hol-guard-entry.py"

PAGER_CASES = [
    (None, False),
    ("", True),
    ("cat", True),
    ("less", True),
    ("less -R", True),
    ("less -FRX -S", True),
    ("more", False),
    ("delta", False),
    ("less; touch x", False),
    ("less --lesskey-src=x", False),
    # These options read the rest of the word as a file name or pattern.
    ("less -Ovictim", False),
    ("less -R -ovictim", False),
    ("less -klesskey", False),
    ("less -Ttags", False),
    ("less -Pprompt", False),
    ("less -+R", False),
]


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _set_pagers(monkeypatch: pytest.MonkeyPatch, pager: str | None) -> None:
    for name in ("PAGER", "GIT_PAGER"):
        if pager is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, pager)


@pytest.mark.parametrize(("pager", "expected"), PAGER_CASES)
def test_python_senders_agree_on_default_equivalent_pagers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pager: str | None,
    expected: bool,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    script = guard_home / "zcode.py"
    script.write_text(
        _render_bounded_hook_script(guard_home=guard_home, harness="zcode", timeout_seconds=8),
        encoding="utf-8",
    )
    generated = _load(script, "generated_zcode_pager_hook")
    entry = _load(FROZEN_ENTRYPOINT, "hol_guard_entry_pager_test")
    _set_pagers(monkeypatch, pager)

    stamped = json.loads(generated._stamp_hook_input(json.dumps({"hook_event_name": "PreToolUse"})))
    context = stamped[HOOK_EXECUTION_ENVIRONMENT_KEY]
    frozen = entry._codex_execution_environment()

    assert pager_default_equivalent(pager) is expected
    assert context["pager_disabled"] is context["git_pager_disabled"] is expected
    assert frozen["pager_disabled"] is frozen["git_pager_disabled"] is expected


def test_stamp_keeps_near_limit_input_forwardable(tmp_path: Path) -> None:
    text = json.dumps({"hook_event_name": "PreToolUse", "tool_input": {"command": "x" * 999_800}})
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    script = guard_home / "zcode.py"
    script.write_text(
        _render_bounded_hook_script(guard_home=guard_home, harness="zcode", timeout_seconds=8),
        encoding="utf-8",
    )
    generated = _load(script, "generated_zcode_size_hook")

    assert stamp_hook_input_text(text) == text
    assert generated._stamp_hook_input(text) == text


def test_frozen_bridge_drops_context_rather_than_exceed_request_limit() -> None:
    entry = _load(FROZEN_ENTRYPOINT, "hol_guard_entry_size_test")
    text = json.dumps({"hook_event_name": "PostToolUse", "tool_response": "x" * 999_800})

    hinted = entry._codex_hint_hook_data(text, event_name="PostToolUse", deadline=1e12, rpc_deadline=1e12)

    assert len(hinted) <= entry._CODEX_HOOK_MAX_INPUT_BYTES
    assert HOOK_EXECUTION_ENVIRONMENT_KEY not in json.loads(hinted)
    small = entry._codex_hint_hook_data("{}", event_name="PostToolUse", deadline=1e12, rpc_deadline=1e12)
    assert HOOK_EXECUTION_ENVIRONMENT_KEY in json.loads(small)


def test_frozen_bridge_forwards_original_input_when_hints_leave_no_room() -> None:
    entry = _load(FROZEN_ENTRYPOINT, "hol_guard_entry_hint_room_test")
    text = json.dumps({"hook_event_name": "PostToolUse", "tool_response": "x" * 999_930})

    hinted = entry._codex_hint_hook_data(text, event_name="PostToolUse", deadline=1e12, rpc_deadline=1e12)

    assert len(text) <= entry._CODEX_HOOK_MAX_INPUT_BYTES
    assert hinted == text
