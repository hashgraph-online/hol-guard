"""Regression coverage for the Desktop updater's executable ownership routing."""

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_commands, update_desktop_core
from codex_plugin_scanner.guard.cli.update_desktop_core import executable_is_desktop_core


def test_frozen_promoted_linux_bundle_uses_desktop_updater_without_launch_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "org.hol.guard.desktop" / "core" / "bundled" / "3.20.2-digest" / "bin" / "hol-guard"
    executable.parent.mkdir(parents=True)
    executable.write_text("core", encoding="utf-8")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)
    assert update_desktop_core.is_desktop_managed_runtime() is True
    assert update_commands._is_desktop_managed_runtime() is True


def test_bundle_path_alone_does_not_make_python_desktop_managed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "org.hol.guard.desktop/core/bundled/bin/python"))
    monkeypatch.delenv("HOL_GUARD_DESKTOP", raising=False)
    assert update_desktop_core.is_desktop_managed_runtime() is False


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("org.hol.guard.desktop/core/bundled/release/bin/hol-guard", True),
        ("hol-desktop/core/bundled/release/bin/hol-guard", True),
        ("hol-desktop/core/bundled/release/lib/hol-guard-core/hol-guard", True),
        ("other-org.hol.guard.desktop/core/bundled/release/bin/hol-guard", False),
        ("org.hol.guard.desktop/core/bundled/release/lib/other-core/hol-guard", False),
        ("org.hol.guard.desktop/core/bundled/release/bin/python", False),
        ("org.hol.guard.desktop/core/bundled/release/bin/nested/hol-guard", False),
    ],
)
def test_updater_recognizes_only_supported_bundled_executables(tmp_path: Path, relative: str, expected: bool) -> None:
    executable = tmp_path / relative
    executable.parent.mkdir(parents=True)
    executable.write_text("frozen core", encoding="utf-8")
    assert executable_is_desktop_core(executable) is expected
