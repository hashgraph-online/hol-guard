"""Grok hook readiness binds every generated launch form to its actual owner."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext, _shell_command
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter, grok_runtime_hooks_verified
from codex_plugin_scanner.guard.cli.grok_hook_validation import is_grok_hook_command
from codex_plugin_scanner.guard.cli.native_install_checks import grok_hooks_protection_ready


def _context(tmp_path: Path, *, workspace: bool = True) -> HarnessContext:
    """Select an explicit home and an optional workspace for a real generated hook."""
    return HarnessContext(tmp_path / "home", tmp_path / "workspace" if workspace else None, tmp_path / "guard")


def _redirect(command: tuple[str, ...], target: Path, option: str) -> tuple[str, ...]:
    """Change paired configuration values while keeping the command internally consistent."""
    offset = 7 if len(command) == 9 else len(command) - 1
    config = json.loads(command[offset])
    args = config["cli_args"]
    args[args.index(option) + 1] = str(target)
    if option == "--guard-home":
        config["guard_home"] = str(target)
    changed = list(command)
    changed[offset] = json.dumps(config)
    return tuple(changed)


def _generated(context: HarnessContext, mode: str, monkeypatch: pytest.MonkeyPatch) -> tuple[str, ...]:
    """Generate native Python/frozen hooks or the signed desktop proxy envelope."""
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)
    if mode == "frozen":
        monkeypatch.setattr(sys, "frozen", True, raising=False)
    command = GrokHarnessAdapter._hook_command_parts(context)
    if mode != "desktop":
        return command
    from codex_plugin_scanner.guard.adapters import desktop_hook_proxy as proxy

    bundle = context.home_dir / "Guard.app"
    candidate = bundle / "Contents/MacOS/proxy"
    core = candidate.with_name("core")
    config = json.loads(command[-1])
    config.update(frozen_launcher=True, python_executable=str(core))
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(proxy, "_trusted_desktop_path", lambda _path: True)
    monkeypatch.setattr(proxy, "_codesign_team", lambda _path: "TEAM123")
    return (
        "/bin/sh",
        "-c",
        proxy._DESKTOP_PROXY_LAUNCH_SCRIPT,
        "hol-guard-desktop-proxy",
        str(candidate),
        "TEAM123",
        str(bundle),
        json.dumps(config),
        str(core),
    )


@pytest.mark.security_critical
@pytest.mark.parametrize("mode", ["python", "frozen", "desktop"])
@pytest.mark.parametrize("option", ["--guard-home", "--home", "--workspace"])
def test_all_generated_forms_reject_paired_path_redirects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, option: str
) -> None:
    """Valid signatures and internally consistent arguments cannot authorize another context."""
    if mode == "desktop" and os.name == "nt":
        pytest.skip("The signed macOS proxy uses POSIX command serialization.")
    context = _context(tmp_path)
    command = _generated(context, mode, monkeypatch)
    assert is_grok_hook_command(_shell_command(command), context)
    changed = _redirect(command, tmp_path / "redirected", option)
    assert is_grok_hook_command(_shell_command(changed))  # Syntax alone is intentionally insufficient.
    assert not is_grok_hook_command(_shell_command(changed), context)


@pytest.mark.security_critical
@pytest.mark.parametrize("pinned", [False, True])
def test_workspace_boundaries_are_not_interchangeable(tmp_path: Path, pinned: bool) -> None:
    """A workspace-specific hook cannot claim machine-wide coverage, or vice versa."""
    context = _context(tmp_path, workspace=pinned)
    command = _shell_command(GrokHarnessAdapter._hook_command_parts(context))
    assert is_grok_hook_command(command, context)
    assert not is_grok_hook_command(command, _context(tmp_path, workspace=not pinned))


def test_implicit_native_home_must_match_current_user(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The generator may omit --home only when the process's home is the intended one."""
    context = _context(tmp_path, workspace=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: context.home_dir))
    command = _shell_command(GrokHarnessAdapter._hook_command_parts(context))
    assert is_grok_hook_command(command, context)
    assert not is_grok_hook_command(command, replace(context, home_dir=tmp_path / "other-home"))


@pytest.mark.security_critical
@pytest.mark.parametrize("option", ["--guard-home", "--home", "--workspace"])
def test_installed_readiness_rejects_consistent_path_redirects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, option: str
) -> None:
    """Both public readiness paths bind on-disk hook configuration to the supplied owner."""
    context = _context(tmp_path)
    monkeypatch.delenv("GROK_HOME", raising=False)
    adapter = GrokHarnessAdapter()
    adapter.install(context)
    assert grok_runtime_hooks_verified(context)
    assert grok_hooks_protection_ready(context)
    hook = adapter._hooks_dir(context) / "hol-guard-pretooluse.json"
    payload = json.loads(hook.read_text())
    command = _redirect(adapter._hook_command_parts(context), tmp_path / "redirected", option)
    payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = _shell_command(command)
    hook.write_text(json.dumps(payload), encoding="utf-8")
    assert not grok_runtime_hooks_verified(context)
    assert not grok_hooks_protection_ready(context)
