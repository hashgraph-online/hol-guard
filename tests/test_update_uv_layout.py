"""A uv tool environment moved with UV_TOOL_DIR stays updatable, and only through its own launcher."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_commands, update_subprocess
from codex_plugin_scanner.guard.cli.update_subprocess import UpdateSubprocessError
from codex_plugin_scanner.guard.cli.update_uv_layout import custom_uv_tool_layout, is_uv_tool_environment

pytestmark = pytest.mark.skipif(os.name == "nt", reason="uv links launchers only on POSIX")


def _tool_environment(root: Path, *, name: str = "hol-guard", receipt: bool = True) -> Path:
    prefix = root / "custom-tools" / name
    (prefix / "bin").mkdir(parents=True)
    (prefix / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (prefix / "bin" / "hol-guard").write_text("#!/bin/sh\n", encoding="utf-8")
    if receipt:
        (prefix / "uv-receipt.toml").write_text("[tool]\n", encoding="utf-8")
    return prefix


def _launcher_dir(root: Path, target: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    bin_dir = root / "custom-bin"
    bin_dir.mkdir()
    (bin_dir / "hol-guard").symlink_to(target)
    monkeypatch.setenv("UV_TOOL_BIN_DIR", str(bin_dir))
    return bin_dir


def test_custom_tool_directory_resolves_through_the_linked_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = _tool_environment(tmp_path)
    bin_dir = _launcher_dir(tmp_path, prefix / "bin" / "hol-guard", monkeypatch)

    assert is_uv_tool_environment(prefix)
    assert custom_uv_tool_layout(prefix) == (prefix.parent, bin_dir)


def test_custom_tool_directory_rejects_a_launcher_for_another_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = _tool_environment(tmp_path)
    other = tmp_path / "other" / "hol-guard"
    other.parent.mkdir()
    other.write_text("#!/bin/sh\n", encoding="utf-8")
    _launcher_dir(tmp_path, other, monkeypatch)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    assert custom_uv_tool_layout(prefix) is None


def test_custom_tool_directory_rejects_a_copied_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prefix = _tool_environment(tmp_path)
    bin_dir = tmp_path / "custom-bin"
    bin_dir.mkdir()
    (bin_dir / "hol-guard").write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("UV_TOOL_BIN_DIR", str(bin_dir))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    assert custom_uv_tool_layout(prefix) is None


@pytest.mark.parametrize(("name", "receipt"), [("hol-guard", False), ("other-tool", True)])
def test_custom_tool_directory_needs_a_uv_receipt_and_the_guard_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, receipt: bool
) -> None:
    prefix = _tool_environment(tmp_path, name=name, receipt=receipt)
    _launcher_dir(tmp_path, prefix / "bin" / "hol-guard", monkeypatch)

    assert custom_uv_tool_layout(prefix) is None


def test_installer_kind_recognizes_uv_in_a_custom_tool_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = _tool_environment(tmp_path)
    monkeypatch.setattr(update_commands.sys, "prefix", str(prefix))

    assert update_commands._installer_kind() == "uv"


def test_installer_kind_recognizes_uv_from_the_runtime_path_in_a_custom_tool_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = _tool_environment(tmp_path)
    runtime_path = prefix / "lib/python3/site-packages/guard/update_commands.py"
    runtime_path.parent.mkdir(parents=True)
    base_prefix = tmp_path / "python-runtime"
    base_prefix.mkdir()
    monkeypatch.setattr(update_commands.sys, "prefix", str(base_prefix))
    monkeypatch.setattr(update_commands, "_runtime_package_path", lambda: runtime_path)

    assert update_commands._installer_kind() == "uv"


def test_manager_home_uses_the_custom_uv_layout_and_keeps_pipx_strict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prefix = _tool_environment(tmp_path)
    bin_dir = _launcher_dir(tmp_path, prefix / "bin" / "hol-guard", monkeypatch)
    monkeypatch.setattr(update_subprocess.sys, "prefix", str(prefix))

    assert update_subprocess._manager_home_from_prefix("uv") == (prefix.parent.resolve(), bin_dir)
    with pytest.raises(UpdateSubprocessError) as error:
        update_subprocess._manager_home_from_prefix("pipx")
    assert error.value.reason_code == "update_installer_untrusted"


def test_uv_is_never_looked_up_in_a_custom_launcher_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prefix = _tool_environment(tmp_path)
    bin_dir = _launcher_dir(tmp_path, prefix / "bin" / "hol-guard", monkeypatch)
    planted = bin_dir / "uv"
    planted.write_text("#!/bin/sh\n", encoding="utf-8")
    planted.chmod(0o755)
    user_bin = tmp_path / "account-home" / ".local" / "bin"
    user_bin.mkdir(parents=True)
    monkeypatch.setattr(update_subprocess.sys, "prefix", str(prefix))
    monkeypatch.setattr(update_subprocess, "uv_user_bin_dir", lambda: user_bin)

    entries = update_subprocess._trusted_runtime_search_path(installer_kind="uv").split(os.pathsep)

    assert str(bin_dir.resolve()) not in entries
    assert str(user_bin.resolve()) in entries


def test_an_account_without_a_password_entry_still_searches_the_system_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import pwd

    prefix = _tool_environment(tmp_path)
    bin_dir = _launcher_dir(tmp_path, prefix / "bin" / "hol-guard", monkeypatch)
    monkeypatch.setattr(update_subprocess.sys, "prefix", str(prefix))

    def missing(_uid: int) -> object:
        raise KeyError("no entry")

    monkeypatch.setattr(pwd, "getpwuid", missing)

    entries = update_subprocess._trusted_runtime_search_path(installer_kind="uv").split(os.pathsep)

    assert entries
    assert str(bin_dir.resolve()) not in entries
