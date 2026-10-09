"""Pager values every hook sender reports as no wider than Git's default pager."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner.guard.adapters import pi_extension_source
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


def test_all_senders_keep_present_but_empty_pager_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    script = guard_home / "zcode.py"
    script.write_text(
        _render_bounded_hook_script(guard_home=guard_home, harness="zcode", timeout_seconds=8),
        encoding="utf-8",
    )
    generated = _load(script, "generated_zcode_empty_pager_hook")
    entry = _load(FROZEN_ENTRYPOINT, "hol_guard_entry_empty_pager_test")
    monkeypatch.setenv("GIT_PAGER", "")
    monkeypatch.setenv("PAGER", "delta")

    contexts = [
        json.loads(stamp_hook_input_text("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY],
        json.loads(generated._stamp_hook_input("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY],
        entry._codex_execution_environment(),
    ]
    for context in contexts:
        assert "GIT_PAGER" in context["environment_names"]
        assert "PAGER" in context["environment_names"]
        assert context["git_pager_disabled"] is True
        assert context["pager_disabled"] is False
    assert len({tuple(c["environment_names"]) for c in contexts}) == 1
    assert len({c["environment_digest"] for c in contexts}) == 1

    monkeypatch.delenv("GIT_PAGER")
    unset = json.loads(stamp_hook_input_text("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY]
    assert "GIT_PAGER" not in unset["environment_names"]


def _pi_execution_environment(tmp_path: Path, env: dict[str, str]) -> dict[str, object]:
    source = pi_extension_source.managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )
    start = source.index("  const activeEnvironment = Object.create(null);")
    end = source.index("  let serializedPayload = '';", start)
    script = tmp_path / "pi-environment.mjs"
    script.write_text(
        'import { createHash } from "node:crypto";\n'
        "const payload = {};\n"
        f"{source[start:end]}"
        "console.log(JSON.stringify(payloadToSend.guard_execution_environment));\n",
        encoding="utf-8",
    )
    result = subprocess.run(["node", str(script)], env=env, capture_output=True, text=True, timeout=30, check=True)
    return json.loads(result.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="the Pi extension runs under node")
def test_pi_sender_keeps_present_but_empty_pager_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_PAGER", "")
    monkeypatch.setenv("PAGER", "delta")
    env = dict(os.environ)

    pi = _pi_execution_environment(tmp_path, env)
    python = json.loads(stamp_hook_input_text("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY]

    assert "GIT_PAGER" in pi["environment_names"]
    assert pi["git_pager_disabled"] is True
    assert pi["pager_disabled"] is False
    assert pi["environment_names"] == python["environment_names"]
    assert pi["environment_digest"] == python["environment_digest"]

    del env["GIT_PAGER"]
    unset = _pi_execution_environment(tmp_path, env)
    assert "GIT_PAGER" not in unset["environment_names"]
    assert unset["git_pager_disabled"] is False
