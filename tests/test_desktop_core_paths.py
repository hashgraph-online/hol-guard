"""Regression coverage for the Desktop updater's executable ownership routing."""

import plistlib
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import desktop_core_paths, update_commands, update_desktop_core
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


def _write_app(bundle: Path, *, bundle_id: str, version: str) -> Path:
    contents = bundle / "Contents"
    contents.mkdir(parents=True)
    with (contents / "Info.plist").open("wb") as handle:
        plistlib.dump({"CFBundleIdentifier": bundle_id, "CFBundleShortVersionString": version}, handle)
    return bundle


def test_installed_desktop_app_version_takes_the_oldest_guard_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundles = (
        _write_app(tmp_path / "system" / "HOL Guard.app", bundle_id="org.hol.guard.desktop", version="3.0.145"),
        _write_app(tmp_path / "user" / "HOL Guard.app", bundle_id="org.hol.guard.desktop", version="3.0.120"),
        _write_app(tmp_path / "other" / "HOL Guard.app", bundle_id="com.example.other", version="0.0.1"),
        tmp_path / "missing" / "HOL Guard.app",
    )
    monkeypatch.setattr(desktop_core_paths, "desktop_app_bundles", lambda: bundles)
    assert str(desktop_core_paths.installed_desktop_app_version()) == "3.0.120"


def test_installed_desktop_app_version_is_none_without_a_readable_app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broken = tmp_path / "broken" / "HOL Guard.app"
    (broken / "Contents").mkdir(parents=True)
    (broken / "Contents" / "Info.plist").write_bytes(b"not a plist")
    unversioned = _write_app(tmp_path / "bad" / "HOL Guard.app", bundle_id="org.hol.guard.desktop", version="dev")
    monkeypatch.setattr(desktop_core_paths, "desktop_app_bundles", lambda: (broken, unversioned))
    assert desktop_core_paths.installed_desktop_app_version() is None
