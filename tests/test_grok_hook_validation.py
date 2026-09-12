"""Generated Grok invocations, permission tables, and readable repair diagnostics."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext, _shell_command
from codex_plugin_scanner.guard.adapters.grok import GrokHarnessAdapter
from codex_plugin_scanner.guard.cli.grok_hook_validation import is_grok_hook_command
from codex_plugin_scanner.guard.cli.native_install_checks import (
    _grok_managed_config_is_active,
    _grok_protection_checks,
)


def _command(tmp_path: Path) -> tuple[str, ...]:
    """Use the real generator so validation remains compatible with installed hooks."""
    context = HarnessContext(tmp_path / "home", tmp_path / "workspace", tmp_path / "guard")
    return GrokHarnessAdapter._hook_command_parts(context)


def test_generated_grok_bridge_is_recognized(tmp_path: Path) -> None:
    """The current interpreter, isolated bootstrap, and Grok arguments are accepted."""
    assert is_grok_hook_command(_shell_command(_command(tmp_path))) is True


@pytest.mark.parametrize("mutation", ["bootstrap", "executable", "harness", "home", "extra", "shell", "malformed"])
def test_grok_bridge_rejects_marker_only_or_modified_invocations(tmp_path: Path, mutation: str) -> None:
    """Marker strings cannot make an ineffective or redirected command report ready."""
    command = list(_command(tmp_path))
    config = json.loads(command[-1])
    if mutation == "bootstrap":
        command[3] = "print('bounded_cli_hook_bridge hol-guard hook')"
    elif mutation == "executable":
        command[0] = config["python_executable"] = "/bin/echo"
    elif mutation == "harness":
        config["cli_args"][5] = "pi"
    elif mutation == "home":
        config["guard_home"] = str(tmp_path / "another")
    elif mutation == "extra":
        config["cli_args"] += ["--help"]
    elif mutation == "shell":
        command = ["sh", "-c", "echo hol-guard hook"]
    elif mutation == "malformed":
        return_value = is_grok_hook_command("'unterminated")
        assert return_value is False
        return
    if mutation != "shell":
        command[-1] = json.dumps(config)
    assert is_grok_hook_command(_shell_command(tuple(command))) is False


def test_frozen_generated_grok_bridge_is_recognized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Packaged Core hooks retain the supported frozen bridge form."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)
    assert is_grok_hook_command(_shell_command(_command(tmp_path))) is True


@pytest.mark.skipif(os.name == "nt", reason="macOS signed proxy uses POSIX shell serialization")
def test_desktop_grok_proxy_requires_all_signatures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The known proxy script needs matching verified bundle, proxy, and Core teams."""
    from codex_plugin_scanner.guard.adapters import desktop_hook_proxy as proxy

    base = _command(tmp_path)
    config = json.loads(base[-1])
    bundle = tmp_path / "Guard.app"
    candidate = bundle / "Contents/MacOS/proxy"
    core = candidate.with_name("core")
    config.update(frozen_launcher=True, python_executable=str(core))
    command = (
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
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(proxy, "_trusted_desktop_path", lambda _path: True)
    monkeypatch.setattr(proxy, "_codesign_team", lambda _path: "TEAM123")
    assert is_grok_hook_command(_shell_command(command)) is True
    monkeypatch.setattr(proxy, "_codesign_team", lambda path: None if path == core else "TEAM123")
    assert is_grok_hook_command(_shell_command(command)) is False
    altered = (*command[:2], "echo hol-guard hook", *command[3:])
    assert is_grok_hook_command(_shell_command(altered)) is False


@pytest.mark.parametrize(
    "table",
    [
        '[permission]\nallow = ["Read(**/.grok/auth/**)"]',
        '[other]\ndeny = ["Read(**/.grok/auth/**)"]',
        'deny = ["Read(**/.grok/auth/**)"]',
        "[permission]\ndeny = [] # Read(**/.grok/auth/**)",
        '[permission]\ndeny = "Read(**/.grok/auth/**)"',
        '[permission]\ndeny = ["Read(**/.grok/auth/**)"',
    ],
)
def test_grok_readiness_requires_real_permission_deny_list(table: str) -> None:
    """Rules in allow, unrelated tables, comments, or invalid TOML do not protect secrets."""
    assert (
        _grok_managed_config_is_active(f"# BEGIN HOL GUARD MANAGED GROK\n{table}\n# END HOL GUARD MANAGED GROK\n")
        is False
    )


@pytest.mark.parametrize("error", ["unicode", "io"])
def test_unreadable_grok_managed_config_returns_repair_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: str
) -> None:
    """Unreadable settings degrade readiness rather than breaking status/repair callers."""
    context = HarnessContext(tmp_path / "home", None, tmp_path / "guard")
    monkeypatch.delenv("GROK_HOME", raising=False)
    path = context.home_dir / ".grok/managed_config.toml"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\xff")
    original = Path.read_text

    def read(candidate: Path, *args: object, **kwargs: object) -> str:
        """Make only the managed TOML path fail as an unreadable file."""
        if candidate == path and error == "io":
            raise OSError("unreadable")
        return original(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    checks = _grok_protection_checks(context)
    assert checks["ready"] is False
    assert any("could not be read" in warning for warning in checks["warnings"])
