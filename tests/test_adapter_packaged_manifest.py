"""Install-time file identities must survive internal adapter reorganization."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex, codex_daemon_hook_resume
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.codex_hook_integrity import (
    hook_manifest_path,
    load_authenticated_hook_manifest_path,
)
from codex_plugin_scanner.guard.codex_hook_runtime_trust import verify_captured_launch_generation


def test_codex_manifest_files_include_the_real_resume_implementation() -> None:
    files = dict(codex._hook_packaged_file_paths())
    assert files["bridge_resume"] == Path(codex_daemon_hook_resume.__file__).resolve()
    assert files["bridge_resume"].parent == Path(codex.__file__).resolve().parent
    assert all(path.is_file() for path in files.values())


def test_installed_codex_manifest_verifies_after_adapter_reorganization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    config = home / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    original = "[features]\nhooks = true\n"
    config.write_text(original, encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    context = HarnessContext(home_dir=home, workspace_dir=None, guard_home=home / ".hol-guard")
    codex.CodexHarnessAdapter().install(context)
    manifest = load_authenticated_hook_manifest_path(context.guard_home, hook_manifest_path(context.guard_home, config))
    _, packaged = verify_captured_launch_generation(manifest)
    assert packaged["bridge_resume"]["path"] == str(Path(codex_daemon_hook_resume.__file__).resolve())
