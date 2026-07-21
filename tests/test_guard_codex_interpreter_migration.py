"""Codex managed-hook reinstallation coverage for interpreter relocation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex as codex_adapter
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.codex_hook_integrity import HOOK_MANIFEST_SCHEMA_VERSION
from codex_plugin_scanner.guard.codex_hook_package_identity import assert_package_reauthentication_is_safe


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable fixtures are required")
def test_guard_install_codex_adopts_equivalent_package_with_relocated_interpreter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )
    first_interpreter = tmp_path / "first-python"
    second_interpreter = tmp_path / "second-python"
    for interpreter in (first_interpreter, second_interpreter):
        interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        interpreter.chmod(0o755)

    monkeypatch.setattr(codex_adapter.sys, "executable", str(first_interpreter))
    adapter = CodexHarnessAdapter()
    adapter.install(context)

    monkeypatch.setattr(codex_adapter.sys, "executable", str(second_interpreter))
    installed = adapter.install(context)
    state = codex_adapter.codex_native_hook_state(context)

    assert installed["active"] is True
    assert state["protection_active"] is True


def test_reauthentication_rejects_incomplete_package_identity() -> None:
    manifest = {
        "schema_version": HOOK_MANIFEST_SCHEMA_VERSION,
        "package_version": "2.1.0a6",
        "packaged_files": [],
    }

    with pytest.raises(CodexHookIntegrityError, match="changed same-version hook code"):
        assert_package_reauthentication_is_safe(manifest, manifest)
