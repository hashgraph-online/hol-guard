"""Regression tests for updater runtime-path classification."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_commands


def test_runtime_installer_kind_uses_path_protocol_without_as_posix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "pipx/venvs/hol-guard"
    runtime_path = runtime_root / "lib/python3/site-packages/guard/update_commands.py"
    runtime_path.parent.mkdir(parents=True)
    (runtime_root / "pipx_metadata.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(update_commands, "_runtime_package_path", lambda: runtime_path)

    def reject_as_posix(_path: Path) -> str:
        raise AssertionError("runtime installer discovery must use the path protocol")

    monkeypatch.setattr(type(runtime_path), "as_posix", reject_as_posix)

    assert update_commands._runtime_installer_kind() == "pipx"
