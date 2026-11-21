"""Installed Grok hook readiness binds the on-disk hook to its actual owner.

The launch forms and their owner binding are covered by the native runtime's Rust tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.native_install_checks import (
    grok_hooks_protection_ready,
    grok_runtime_hooks_verified,
)
from codex_plugin_scanner.guard.diagnostics_bridge import shell_command as _shell_command
from codex_plugin_scanner.guard.harness_context import HarnessContext
from tests import harness_ops_support as harness_support
from tests.native_bounded_runtime import use_bounded_runtime

from .grok_test_support import grok_hook_command_parts, grok_paths


def _context(tmp_path: Path, *, workspace: bool = True) -> HarnessContext:
    """Select an explicit home and an optional workspace for a real generated hook."""
    return HarnessContext(tmp_path / "home", tmp_path / "workspace" if workspace else None, tmp_path / "guard")


def _redirect(command: tuple[str, ...], target: Path, option: str) -> tuple[str, ...]:
    """Change paired configuration values while keeping the command internally consistent."""
    offset = 7 if len(command) == 10 else len(command) - 1
    config = json.loads(command[offset])
    args = config["cli_args"]
    args[args.index(option) + 1] = str(target)
    if option == "--guard-home":
        config["guard_home"] = str(target)
    changed = list(command)
    changed[offset] = json.dumps(config)
    return tuple(changed)


@pytest.fixture(autouse=True)
def _runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The host's native runtime, as install and validation both find it."""
    runtime = tmp_path / "hol-guard-runtime"
    use_bounded_runtime(monkeypatch, runtime, tmp_path / "guard")


@pytest.mark.security_critical
@pytest.mark.parametrize("option", ["--guard-home", "--home", "--workspace"])
def test_installed_readiness_rejects_consistent_path_redirects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, option: str
) -> None:
    """Both public readiness paths bind on-disk hook configuration to the supplied owner."""
    context = _context(tmp_path)
    monkeypatch.delenv("GROK_HOME", raising=False)
    harness_support.install("grok", context)
    assert grok_runtime_hooks_verified(context)
    assert grok_hooks_protection_ready(context)
    hook = grok_paths(context)["pretool"]
    payload = json.loads(hook.read_text())
    command = _redirect(grok_hook_command_parts(context), tmp_path / "redirected", option)
    payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = _shell_command(command)
    hook.write_text(json.dumps(payload), encoding="utf-8")
    assert not grok_runtime_hooks_verified(context)
    assert not grok_hooks_protection_ready(context)
