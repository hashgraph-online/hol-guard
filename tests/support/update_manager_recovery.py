"""Native manager setup for the authenticated recovery-command contract."""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_subprocess as update_subprocess_module
from codex_plugin_scanner.guard.cli.update_subprocess import TrustedUpdateContext


def build_manager_recovery_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, source_url: str
) -> tuple[TrustedUpdateContext, Path]:
    if os.name != "nt":
        from tests.test_guard_update_subprocess import _build_manager_context

        return _build_manager_context(tmp_path, monkeypatch, "pipx", source_url=source_url)

    trusted_import_paths = update_subprocess_module._trusted_python_import_paths()
    profile = tmp_path / "windows-profile"
    manager = profile / ".local" / "bin" / "pipx.exe"
    manager.parent.mkdir(parents=True)
    shutil.copy2(sys.executable, manager)
    prefix = profile / "pipx" / "venvs" / "hol-guard"
    prefix.mkdir(parents=True)
    monkeypatch.setattr(update_subprocess_module.sys, "prefix", str(prefix))
    monkeypatch.setattr(update_subprocess_module, "_trusted_python_import_paths", lambda: trusted_import_paths)
    monkeypatch.setattr(update_subprocess_module, "trusted_windows_user_profile", lambda: profile)
    return update_subprocess_module.build_trusted_update_context(
        guard_home=tmp_path / "guard-home", workspace_dir=tmp_path / "workspace",
        installer_kind="pipx", source_url=source_url, proxy_mode="none",
    ), manager
