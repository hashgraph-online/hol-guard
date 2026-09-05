from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.adapters.grok_config import (
    GROK_PRETOOL_HOOK_TIMEOUT_SECONDS,
    GUARD_HOOK_PRETOOL_FILE,
)
from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.update_grok_repair import repair_grok_install
from codex_plugin_scanner.guard.store import GuardStore


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir()
    guard_home = home / ".hol-guard"
    guard_home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard_home)


def _seed_grok_install(context: HarnessContext, store: GuardStore, now: str) -> Path:
    adapter = GrokHarnessAdapter()
    manifest = adapter.install(context)
    store.set_managed_install("grok", True, None, manifest, now)
    return adapter._hooks_dir(context) / GUARD_HOOK_PRETOOL_FILE


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
    assert payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == GROK_PRETOOL_HOOK_TIMEOUT_SECONDS


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
    assert payload["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] == GROK_PRETOOL_HOOK_TIMEOUT_SECONDS


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


def test_grok_repair_rewrites_missing_hook_executable(tmp_path: Path) -> None:
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


def test_grok_repair_rewrites_hooks_without_json_flag(tmp_path: Path) -> None:
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


def _sample_hook_config(tmp_path: Path) -> dict[str, object]:
    return {
        "python_executable": str(tmp_path / "o'brien" / "python"),
        "package_root": str(tmp_path),
        "guard_home": str(tmp_path / "guard-home"),
        "cli_args": ["guard", "hook", "--harness", "grok", "--json"],
        "harness": "grok",
        "timeout_seconds": 25,
        "frozen_launcher": True,
    }


def test_hook_config_from_desktop_proxy_command_ignores_script_braces(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.base import _shell_command
    from codex_plugin_scanner.guard.adapters.desktop_hook_proxy import _DESKTOP_PROXY_LAUNCH_SCRIPT
    from codex_plugin_scanner.guard.cli.update_grok_repair import _hook_config_from_command

    config = _sample_hook_config(tmp_path)
    command = _shell_command(
        (
            "/bin/sh",
            "-c",
            _DESKTOP_PROXY_LAUNCH_SCRIPT,
            "hol-guard-desktop-proxy",
            str(tmp_path / "proxy"),
            "TEAMID",
            str(tmp_path / "HOL Guard.app"),
            json.dumps(config, separators=(",", ":")),
            str(tmp_path / "core"),
        ),
        windows=False,
    )
    parsed = _hook_config_from_command(command)
    assert parsed is not None
    assert parsed["python_executable"] == config["python_executable"]
    assert parsed["cli_args"] == config["cli_args"]


def test_hook_config_from_windows_shell_escaped_json(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.base import _shell_command
    from codex_plugin_scanner.guard.cli.update_grok_repair import _hook_config_from_command

    config = _sample_hook_config(tmp_path)
    command = _shell_command(
        (
            str(tmp_path / "python.exe"),
            "__guard-bounded-hook",
            json.dumps(config, separators=(",", ":")),
        ),
        windows=True,
    )
    parsed = _hook_config_from_command(command)
    assert parsed is not None
    assert parsed["python_executable"] == config["python_executable"]
    assert "--json" in parsed["cli_args"]


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
        "codex_plugin_scanner.guard.adapters.grok.sys.executable",
        str(versioned),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.update_grok_repair.sys.executable",
        str(versioned),
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
