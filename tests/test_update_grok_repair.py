from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.native_install_checks import grok_protection
from codex_plugin_scanner.guard.cli.update_grok_repair import repair_grok_install
from codex_plugin_scanner.guard.harness_context import HarnessContext
from codex_plugin_scanner.guard.store import GuardStore
from tests import harness_ops_support as harness_support
from tests.native_bounded_runtime import use_bounded_runtime

_PROMPT_FILE = "hol-guard-prompt.json"


@pytest.fixture(autouse=True)
def runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The host's native runtime, as install and validation both find it."""
    path = tmp_path / "hol-guard-runtime"
    use_bounded_runtime(monkeypatch, path)
    return path


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir()
    guard_home = home / ".hol-guard"
    guard_home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)


def _seed_grok_install(context: HarnessContext, store: GuardStore, now: str) -> Path:
    manifest = harness_support.install("grok", context)
    store.set_managed_install("grok", True, None, manifest, now)
    return Path(grok_protection(context)["pretool_hook_path"])


def _set_pretool_timeout(hook_path: Path, timeout: int) -> None:
    payload = json.loads(hook_path.read_text(encoding="utf-8"))
    payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = timeout
    hook_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_grok_repair_skips_when_hooks_already_current(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"
    hook_path = _seed_grok_install(context, store, now)
    before = hook_path.read_text(encoding="utf-8")

    repaired, warning = repair_grok_install(
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert repaired is None
    assert warning is None
    assert hook_path.read_text(encoding="utf-8") == before


def test_grok_repair_preserves_additional_current_prompt_hooks(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-10-04T00:00:00+00:00"
    prompt = _seed_grok_install(context, store, now).with_name(_PROMPT_FILE)
    payload = json.loads(prompt.read_text())
    payload["custom"] = "keep"
    payload["hooks"]["UserPromptSubmit"][0]["hooks"].append({"type": "command", "command": "echo user-hook"})
    payload["hooks"]["CustomEvent"] = [{"hooks": [{"type": "command", "command": "echo other-hook"}]}]
    before = json.dumps(payload, indent=2) + "\n"
    prompt.write_text(before)

    repaired, warning = repair_grok_install(context=context, store=store, workspace=None, now=now)

    assert (repaired, warning) == (None, None)
    assert prompt.read_text() == before


@pytest.mark.parametrize("stale_kind", ["missing", "timeout", "command"])
def test_grok_repair_checks_prompt_hook_even_when_pretool_is_current(tmp_path: Path, stale_kind: str) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-10-04T00:00:00+00:00"
    pretool = _seed_grok_install(context, store, now)
    prompt = pretool.with_name(_PROMPT_FILE)
    expected = prompt.read_text()
    if stale_kind == "missing":
        prompt.unlink()
    else:
        payload = json.loads(expected)
        hook = payload["hooks"]["UserPromptSubmit"][0]["hooks"][0]
        hook[stale_kind] = 1 if stale_kind == "timeout" else "missing-guard"
        prompt.write_text(json.dumps(payload))

    repaired, warning = repair_grok_install(context=context, store=store, workspace=None, now=now)

    assert warning is None
    assert repaired is not None
    assert prompt.read_text() == expected


def test_grok_repair_moves_an_old_client_to_the_native_hook(tmp_path: Path, runtime: Path) -> None:
    # Older releases registered `python -I <guard-home>/managed/bounded-hooks/grok.py <config>`.
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-10-04T00:00:00+00:00"
    hook_path = _seed_grok_install(context, store, now)
    payload = json.loads(hook_path.read_text())
    entry = payload["hooks"]["PreToolUse"][0]["hooks"][0]
    script = context.guard_home / "managed" / "bounded-hooks" / "grok.py"
    entry["command"] = shlex.join([sys.executable, "-I", str(script), shlex.split(entry["command"])[-1]])
    hook_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    repaired, warning = repair_grok_install(context=context, store=store, workspace=None, now=now)

    assert warning is None
    assert repaired is not None
    command = json.loads(hook_path.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert shlex.split(command)[:2] == [str(runtime), "bounded-hook-bridge"]
    assert repair_grok_install(context=context, store=store, workspace=None, now=now) == (None, None)


def test_grok_repair_rewrites_stale_pretool_timeout(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"
    hook_path = _seed_grok_install(context, store, now)
    _set_pretool_timeout(hook_path, 30)

    repaired, warning = repair_grok_install(
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert warning is None
    assert isinstance(repaired, dict)
    assert repaired.get("harness") == "grok"
    payload = json.loads(hook_path.read_text(encoding="utf-8"))
    assert payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == 90


def test_grok_repair_skips_inactive_install(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"

    repaired, warning = repair_grok_install(
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert repaired is None
    assert warning is None


def test_update_repair_rewrites_stale_grok_hooks(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"
    hook_path = _seed_grok_install(context, store, now)
    _set_pretool_timeout(hook_path, 30)

    repaired, notes = update_commands._repair_supported_harnesses_in_process(
        context=context,
        store=store,
        workspace=None,
        now=now,
        dry_run=False,
    )

    assert notes == []
    assert any(item.get("harness") == "grok" for item in repaired)
    payload = json.loads(hook_path.read_text(encoding="utf-8"))
    assert payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == 90


def _replace_hook_config(hook_path: Path, **updates: object) -> None:
    payload = json.loads(hook_path.read_text(encoding="utf-8"))
    command = payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    start = command.find("{")
    end = command.rfind("}")
    config = json.loads(command[start : end + 1])
    config.update(updates)
    payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = (
        command[:start] + json.dumps(config, separators=(",", ":")) + command[end + 1 :]
    )
    hook_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_grok_repair_rewrites_missing_hook_executable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"
    hook_path = _seed_grok_install(context, store, now)
    _replace_hook_config(hook_path, python_executable=str(tmp_path / "missing-hol-guard"))

    repaired, warning = repair_grok_install(
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert warning is None
    assert isinstance(repaired, dict)
    command = json.loads(hook_path.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "missing-hol-guard" not in command


def test_grok_repair_rewrites_hooks_without_json_flag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"
    hook_path = _seed_grok_install(context, store, now)
    payload = json.loads(hook_path.read_text(encoding="utf-8"))
    command = payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    start = command.find("{")
    end = command.rfind("}")
    config = json.loads(command[start : end + 1])
    config["cli_args"] = [item for item in config["cli_args"] if item != "--json"]
    _replace_hook_config(hook_path, cli_args=config["cli_args"])

    repaired, warning = repair_grok_install(
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert warning is None
    assert isinstance(repaired, dict)
    command = json.loads(hook_path.read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert '"--json"' in command.replace(" ", "")


def test_grok_repair_rewrites_versioned_desktop_core_when_shim_exists(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    core_dir = tmp_path / "core"
    versioned = core_dir / "versions" / "3.0.86" / "hol-guard"
    versioned.parent.mkdir(parents=True)
    versioned.write_text("binary", encoding="utf-8")
    versioned.chmod(0o755)
    shim = core_dir / "current-hol-guard"
    shim.write_text("#!/bin/sh\n", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.bounded_cli_hook_bridge.sys.executable",
        str(versioned),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.bounded_cli_hook_bridge.sys.frozen",
        True,
        raising=False,
    )
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    now = "2026-08-17T00:00:00+00:00"
    hook_path = _seed_grok_install(context, store, now)
    _replace_hook_config(hook_path, python_executable=str(versioned))

    repaired, warning = repair_grok_install(
        context=context,
        store=store,
        workspace=None,
        now=now,
    )

    assert warning is None
    assert isinstance(repaired, dict)
    payload = json.loads(hook_path.read_text(encoding="utf-8"))
    command = payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert str(shim) in command
    assert "/versions/3.0.86/hol-guard" not in command
