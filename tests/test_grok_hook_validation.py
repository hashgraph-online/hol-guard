"""Generated Grok invocations, permission tables, and readable repair diagnostics."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.native_install_checks import (
    _grok_hook_command_is_guard,
    _grok_managed_config_is_active,
    _grok_protection_checks,
)
from codex_plugin_scanner.guard.harness.base import HarnessContext, _shell_command
from tests.native_bounded_runtime import use_bounded_runtime

from .grok_test_support import _ctx, grok_hook_command_parts


@pytest.fixture
def runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The host's native runtime, as install and validation both find it."""
    path = tmp_path / "hol-guard-runtime"
    use_bounded_runtime(monkeypatch, path)
    return path


def _command(tmp_path: Path) -> tuple[str, ...]:
    """Use the real generator so validation remains compatible with installed hooks."""
    context = HarnessContext(tmp_path / "home", tmp_path / "workspace", tmp_path / "guard")
    return grok_hook_command_parts(context)


def test_generated_grok_hook_is_recognized(tmp_path: Path, runtime: Path) -> None:
    """The host runtime, the bridge command and the Grok config are accepted."""
    command = _command(tmp_path)
    assert command[:2] == (str(runtime), "bounded-hook-bridge")
    assert _grok_hook_command_is_guard(_shell_command(command)) is True


def test_frozen_generated_grok_hook_is_recognized(
    tmp_path: Path, runtime: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Packaged Core hooks name the same runtime with a frozen config."""
    del runtime
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)
    command = _command(tmp_path)
    assert json.loads(command[-1])["frozen_launcher"] is True
    # A frozen hook names the durable runtime copy under its Guard home.
    context = HarnessContext(tmp_path / "home", tmp_path / "workspace", tmp_path / "guard")
    assert _grok_hook_command_is_guard(_shell_command(command), context) is True


def test_grok_hook_is_bound_to_its_owner(tmp_path: Path, runtime: Path) -> None:
    """Another home or Guard store does not own the hook."""
    del runtime
    context = HarnessContext(tmp_path / "home", tmp_path / "workspace", tmp_path / "guard")
    command = grok_hook_command_parts(context)
    assert _grok_hook_command_is_guard(_shell_command(command), context) is True
    other = HarnessContext(tmp_path / "other", None, tmp_path / "other-guard")
    assert _grok_hook_command_is_guard(_shell_command(command), other) is False


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
def test_grok_readiness_requires_real_permission_deny_list(table: str, tmp_path: Path) -> None:
    """Rules in allow, unrelated tables, comments, or invalid TOML do not protect secrets."""
    managed = f"# BEGIN HOL GUARD MANAGED GROK\n{table}\n# END HOL GUARD MANAGED GROK\n"
    assert _grok_managed_config_is_active(managed, _ctx(tmp_path)) is False


@pytest.mark.parametrize("error", ["unicode", "io"])
def test_unreadable_grok_managed_config_returns_repair_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: str
) -> None:
    """Unreadable settings degrade readiness rather than breaking status/repair callers."""
    context = HarnessContext(tmp_path / "home", None, tmp_path / "guard")
    monkeypatch.delenv("GROK_HOME", raising=False)
    path = context.home_dir / ".grok/config.toml"
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
