"""Tests for attested OpenCode hook-interpreter resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import guard_cli_attestation
from codex_plugin_scanner.guard.adapters import hook_python as hook_python_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.hook_python import (
    attest_guard_hook_python,
    guard_cli_command,
    resolve_guard_hook_python,
)
from codex_plugin_scanner.guard.adapters.opencode_pretool import pretool_plugin_source


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )


def test_pretool_plugin_source_uses_parent_attested_import_roots(tmp_path: Path) -> None:
    context = _ctx(tmp_path)
    attestation = attest_guard_hook_python(context)

    source = pretool_plugin_source(context)

    assert str(attestation.package_root) in source
    assert str(attestation.cryptography_distribution_root) in source
    assert str(attestation.identity.target_path) in source
    assert attestation.identity.target_sha256 in source


def test_resolve_guard_hook_python_finds_current_interpreter(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    python = resolve_guard_hook_python(ctx)
    assert python.is_file()
    assert "hol-guard-wt" not in str(python)


def test_frozen_guard_cli_command_uses_signed_executable_without_python_module_prefix(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "HOL Guard"
    executable.write_bytes(b"signed-frozen-core")
    executable.chmod(0o755)
    monkeypatch.setattr(hook_python_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(hook_python_module.sys, "executable", str(executable))

    command = guard_cli_command(
        _ctx(tmp_path),
        ["-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy", "--guard-home", "/guard"],
    )

    assert command == [str(executable), "opencode-mcp-proxy", "--guard-home", "/guard"]


def test_frozen_guard_cli_command_rejects_unknown_launch_shape(tmp_path: Path, monkeypatch) -> None:
    executable = tmp_path / "HOL Guard"
    executable.write_bytes(b"signed-frozen-core")
    executable.chmod(0o755)
    monkeypatch.setattr(hook_python_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(hook_python_module.sys, "executable", str(executable))

    with pytest.raises(RuntimeError, match="managed launch contract"):
        guard_cli_command(_ctx(tmp_path), ["unexpected"])


def test_frozen_opencode_hook_runs_signed_executable_directly(tmp_path: Path, monkeypatch) -> None:
    executable = tmp_path / "HOL Guard"
    executable.write_bytes(b"signed-frozen-core")
    executable.chmod(0o755)
    monkeypatch.setattr(guard_cli_attestation.sys, "frozen", True, raising=False)
    monkeypatch.setattr(guard_cli_attestation.sys, "executable", str(executable))

    source = pretool_plugin_source(_ctx(tmp_path))

    assert "const GUARD_FROZEN = true;" in source
    assert "args: GUARD_FROZEN ? guardArgv" in source
    assert str(executable) in source
