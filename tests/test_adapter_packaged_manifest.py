"""Install-time file identities must survive internal adapter reorganization."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_harness_client as codex
from codex_plugin_scanner.guard.codex_hook_file_integrity import _native
from codex_plugin_scanner.guard.codex_hook_integrity import load_authenticated_hook_manifest_path
from codex_plugin_scanner.guard.harness_context import HarnessContext
from tests import harness_ops_support as harness_support
from tests.codex_hook_paths_support import hook_manifest_path
from tests.native_runtime_stamp import stamp_native_runtime


def test_codex_manifest_files_name_the_native_runtime_the_hook_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_bytes(b"fixture")
    context = HarnessContext(
        home_dir=tmp_path / "home", guard_home=tmp_path / "guard", workspace_dir=None, home_override_explicit=True
    )
    stamp_native_runtime(monkeypatch, runtime)
    files = dict(codex._hook_manifest_spec(context).packaged_file_paths)
    assert files["bridge"] == runtime.resolve()
    assert "bridge_resume" not in files
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
    harness_support.install("codex", context)
    manifest = load_authenticated_hook_manifest_path(context.guard_home, hook_manifest_path(context.guard_home, config))
    _native("captured", manifest=manifest)
    files = manifest["packaged_files"]
    assert isinstance(files, list)
    packaged = {item["role"]: item for item in files}
    hook_runtime = Path(manifest["events"][0]["argv"][0]).resolve()
    assert packaged["bridge"]["path"] == str(hook_runtime)
