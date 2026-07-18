"""Tests for platform adapters: macOS, Windows, Linux.

Validates registration management, ownership checks, and collision
detection without touching real system resources. Uses tmp_path for
file-based operations and mocks for subprocess/registry calls.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.guard.tray.contracts import (
    TRAY_REGISTRATION_LABEL,
    TrayBackend,
    TrayCapability,
    TrayPlatform,
    TrayReasonCode,
)


def _capability(platform: TrayPlatform = TrayPlatform.MACOS) -> TrayCapability:
    backend_map = {
        TrayPlatform.MACOS: TrayBackend.APPKIT,
        TrayPlatform.WINDOWS: TrayBackend.WIN32,
        TrayPlatform.LINUX: TrayBackend.APPINDICATOR,
    }
    return TrayCapability(
        platform=platform,
        backend=backend_map.get(platform, TrayBackend.NONE),
        supported=True,
        reason=TrayReasonCode.OK,
        details="test",
    )


# ---------------------------------------------------------------------------
# macOS adapter tests
# ---------------------------------------------------------------------------


class TestMacOSAdapter:
    def test_platform_is_macos(self) -> None:
        from codex_plugin_scanner.guard.tray.platforms.macos import MacOSTrayAdapter

        adapter = MacOSTrayAdapter()
        assert adapter.platform == TrayPlatform.MACOS

    def test_inspect_registration_when_absent(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.macos import MacOSTrayAdapter

        adapter = MacOSTrayAdapter()
        with patch.object(adapter, "_plist_path", return_value=tmp_path / "nonexistent.plist"):
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["installed"] is False

    def test_install_registration_writes_plist(self, tmp_path: Path) -> None:
        import plistlib

        from codex_plugin_scanner.guard.tray.platforms.macos import MacOSTrayAdapter

        adapter = MacOSTrayAdapter()
        plist_path = tmp_path / "test.plist"
        with patch.object(adapter, "_plist_path", return_value=plist_path):
            result = adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(),
                run_at_login=True,
            )
        assert result["installed"] is True
        assert plist_path.is_file()
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert plist["Label"] == TRAY_REGISTRATION_LABEL
        assert plist["RunAtLoad"] is True
        assert "codex_plugin_scanner" in " ".join(plist["ProgramArguments"])

    def test_inspect_registration_after_install(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.macos import MacOSTrayAdapter

        adapter = MacOSTrayAdapter()
        plist_path = tmp_path / "test.plist"
        with patch.object(adapter, "_plist_path", return_value=plist_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(),
                run_at_login=True,
            )
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["installed"] is True
        assert result["owned"] is True

    def test_refuses_to_overwrite_foreign_plist(self, tmp_path: Path) -> None:
        import plistlib

        from codex_plugin_scanner.guard.tray.platforms.macos import MacOSTrayAdapter

        adapter = MacOSTrayAdapter()
        plist_path = tmp_path / "foreign.plist"
        # Write a foreign plist
        with plist_path.open("wb") as f:
            plistlib.dump(
                {
                    "Label": TRAY_REGISTRATION_LABEL,
                    "ProgramArguments": ["/some/other/app", "--foo"],
                },
                f,
            )
        with patch.object(adapter, "_plist_path", return_value=plist_path):
            result = adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(),
            )
        assert result["installed"] is False
        assert result["reason"] == "startup_registration_collision"

    def test_remove_registration(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.macos import MacOSTrayAdapter

        adapter = MacOSTrayAdapter()
        plist_path = tmp_path / "test.plist"
        with patch.object(adapter, "_plist_path", return_value=plist_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(),
            )
            result = adapter.remove_registration(guard_home=tmp_path)
        assert result["removed"] is True
        assert not plist_path.exists()

    def test_remove_registration_when_absent(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.macos import MacOSTrayAdapter

        adapter = MacOSTrayAdapter()
        with patch.object(adapter, "_plist_path", return_value=tmp_path / "nonexistent.plist"):
            result = adapter.remove_registration(guard_home=tmp_path)
        assert result["removed"] is False
        assert result["reason"] == "not_installed"

    def test_refuses_to_remove_foreign_plist(self, tmp_path: Path) -> None:
        import plistlib

        from codex_plugin_scanner.guard.tray.platforms.macos import MacOSTrayAdapter

        adapter = MacOSTrayAdapter()
        plist_path = tmp_path / "foreign.plist"
        with plist_path.open("wb") as f:
            plistlib.dump(
                {
                    "Label": TRAY_REGISTRATION_LABEL,
                    "ProgramArguments": ["/some/other/app"],
                },
                f,
            )
        with patch.object(adapter, "_plist_path", return_value=plist_path):
            result = adapter.remove_registration(guard_home=tmp_path)
        assert result["removed"] is False
        assert result["reason"] == "startup_registration_collision"
        assert plist_path.exists()  # not removed


# ---------------------------------------------------------------------------
# Linux adapter tests
# ---------------------------------------------------------------------------


class TestLinuxAdapter:
    def test_platform_is_linux(self) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        assert adapter.platform == TrayPlatform.LINUX

    def test_inspect_registration_when_absent(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        with patch.object(adapter, "_desktop_path", return_value=tmp_path / "nonexistent.desktop"):
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["installed"] is False

    def test_install_registration_writes_desktop_entry(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            result = adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
                run_at_login=True,
            )
        assert result["installed"] is True
        assert desktop_path.is_file()
        content = desktop_path.read_text()
        assert "[Desktop Entry]" in content
        assert "codex_plugin_scanner" in content
        assert "X-GNOME-Autostart-enabled=true" in content

    def test_inspect_registration_after_install(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["installed"] is True
        assert result["owned"] is True

    def test_refuses_to_overwrite_foreign_entry(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "foreign.desktop"
        desktop_path.write_text(
            "[Desktop Entry]\nType=Application\nName=Other\nExec=/some/other/app\n",
            encoding="utf-8",
        )
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            result = adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        assert result["installed"] is False
        assert result["reason"] == "startup_registration_collision"

    def test_remove_registration(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
            result = adapter.remove_registration(guard_home=tmp_path)
        assert result["removed"] is True
        assert not desktop_path.exists()

    def test_refuses_to_remove_foreign_entry(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "foreign.desktop"
        desktop_path.write_text(
            "[Desktop Entry]\nType=Application\nName=Other\nExec=/some/other/app\n",
            encoding="utf-8",
        )
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            result = adapter.remove_registration(guard_home=tmp_path)
        assert result["removed"] is False
        assert result["reason"] == "startup_registration_collision"
        assert desktop_path.exists()


# ---------------------------------------------------------------------------
# detect_platform_adapter tests
# ---------------------------------------------------------------------------


class TestDetectPlatformAdapter:
    def test_returns_none_on_unsupported_platform(self) -> None:
        with patch("codex_plugin_scanner.guard.tray.contracts.TrayPlatform.current", return_value=None):
            from codex_plugin_scanner.guard.tray.platforms import detect_platform_adapter

            result = detect_platform_adapter()
        assert result is None

    def test_returns_macos_adapter_on_darwin(self) -> None:
        with patch(
            "codex_plugin_scanner.guard.tray.contracts.TrayPlatform.current",
            return_value=TrayPlatform.MACOS,
        ):
            from codex_plugin_scanner.guard.tray.platforms import detect_platform_adapter

            result = detect_platform_adapter()
        assert result is not None
        assert result.platform == TrayPlatform.MACOS

    def test_returns_none_on_import_error(self) -> None:
        # Simulate pyobjc not being available by blocking the macos module import
        import sys

        original = sys.modules.get("codex_plugin_scanner.guard.tray.platforms.macos")
        sys.modules["codex_plugin_scanner.guard.tray.platforms.macos"] = None  # type: ignore[assignment]
        try:
            with patch(
                "codex_plugin_scanner.guard.tray.contracts.TrayPlatform.current",
                return_value=TrayPlatform.MACOS,
            ):
                from codex_plugin_scanner.guard.tray.platforms import detect_platform_adapter

                result = detect_platform_adapter()
            assert result is None
        finally:
            if original is not None:
                sys.modules["codex_plugin_scanner.guard.tray.platforms.macos"] = original
            else:
                sys.modules.pop("codex_plugin_scanner.guard.tray.platforms.macos", None)
