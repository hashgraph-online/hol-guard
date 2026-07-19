"""Tests for the Linux tray platform adapter (XDG autostart desktop entry).

Validates registration management, desktop entry structure, ownership
checks, and collision detection without touching real system resources.
Uses tmp_path for file-based operations and mocks for subprocess calls.
"""

from __future__ import annotations

import stat
from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.guard.tray.contracts import (
    TRAY_REGISTRATION_LABEL,
    TrayBackend,
    TrayCapability,
    TrayPlatform,
    TrayReasonCode,
)


def _capability(platform: TrayPlatform = TrayPlatform.LINUX) -> TrayCapability:
    return TrayCapability(
        platform=platform,
        backend=TrayBackend.APPINDICATOR,
        supported=True,
        reason=TrayReasonCode.OK,
        details="test",
    )


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

    def test_remove_registration_when_absent(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        with patch.object(adapter, "_desktop_path", return_value=tmp_path / "nonexistent.desktop"):
            result = adapter.remove_registration(guard_home=tmp_path)
        assert result["removed"] is False
        assert result["reason"] == "not_installed"

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

    # -----------------------------------------------------------------------
    # Desktop entry structure tests
    # -----------------------------------------------------------------------

    def test_desktop_entry_has_type_application(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        content = desktop_path.read_text()
        assert "Type=Application" in content

    def test_desktop_entry_has_terminal_false(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        content = desktop_path.read_text()
        assert "Terminal=false" in content

    def test_desktop_entry_exec_line_quoted_paths(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        content = desktop_path.read_text()
        for line in content.splitlines():
            if line.startswith("Exec="):
                exec_value = line[len("Exec="):]
                # Both the executable path and guard_home path must be quoted
                assert exec_value.startswith('"')
                # The value after --guard-home must be quoted
                assert '--guard-home "' in exec_value
                break
        else:
            self.fail("No Exec= line found in desktop entry")

    def test_desktop_entry_has_all_standard_keys(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        content = desktop_path.read_text()
        required_keys = [
            "[Desktop Entry]",
            "Type=Application",
            "Name=HOL Guard Tray",
            "Comment=HOL Guard menu bar icon",
            "Exec=",
            "Icon=hol-guard-tray",
            "Terminal=false",
            "X-GNOME-Autostart-enabled=",
            "Hidden=",
            "Categories=Utility;Security;",
            "StartupNotify=false",
        ]
        for key in required_keys:
            assert key in content, f"Missing desktop entry key: {key}"

    # -----------------------------------------------------------------------
    # XDG autostart path tests
    # -----------------------------------------------------------------------

    def test_desktop_path_is_under_config_autostart(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        autostart_dir = tmp_path / ".config" / "autostart"
        with patch.object(adapter, "_desktop_path", return_value=autostart_dir / f"{TRAY_REGISTRATION_LABEL}.desktop"):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        desktop_path = autostart_dir / f"{TRAY_REGISTRATION_LABEL}.desktop"
        assert desktop_path.exists()
        assert str(autostart_dir) == str(desktop_path.parent)
        assert ".config" in str(desktop_path)
        assert "autostart" in str(desktop_path)

    def test_desktop_filename_matches_registration_label(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import DESKTOP_FILENAME, LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / DESKTOP_FILENAME
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        assert desktop_path.exists()
        assert desktop_path.name == f"{TRAY_REGISTRATION_LABEL}.desktop"

    def test_autostart_dir_created_when_missing(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        # Point to a path under a non-existent autostart directory
        autostart_dir = tmp_path / ".config" / "autostart"
        assert not autostart_dir.exists()
        desktop_path = autostart_dir / f"{TRAY_REGISTRATION_LABEL}.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            result = adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        assert result["installed"] is True
        assert autostart_dir.exists()
        assert desktop_path.exists()

    # -----------------------------------------------------------------------
    # Idempotency tests
    # -----------------------------------------------------------------------

    def test_install_is_idempotent(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            result1 = adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
            result2 = adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        assert result1["installed"] is True
        assert result2["installed"] is True
        content1 = desktop_path.read_text()
        content2 = desktop_path.read_text()
        assert content1 == content2

    def test_remove_when_absent_is_idempotent(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        with patch.object(adapter, "_desktop_path", return_value=tmp_path / "nonexistent.desktop"):
            result1 = adapter.remove_registration(guard_home=tmp_path)
            result2 = adapter.remove_registration(guard_home=tmp_path)
        assert result1["removed"] is False
        assert result2["removed"] is False
        assert result1["reason"] == "not_installed"
        assert result2["reason"] == "not_installed"

    def test_inspect_after_remove(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
            adapter.remove_registration(guard_home=tmp_path)
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["installed"] is False

    # -----------------------------------------------------------------------
    # Foreign desktop entry detection tests
    # -----------------------------------------------------------------------

    def test_foreign_entry_different_exec_is_detected(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "foreign.desktop"
        desktop_path.write_text(
            "[Desktop Entry]\nType=Application\nName=Competitor\n"
            "Exec=/opt/competitor/bin/tray --flag\nX-GNOME-Autostart-enabled=true\n",
            encoding="utf-8",
        )
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            result = adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        assert result["installed"] is False
        assert result["reason"] == "startup_registration_collision"

    def test_foreign_entry_has_owned_false(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "foreign.desktop"
        desktop_path.write_text(
            "[Desktop Entry]\nType=Application\nName=Unknown\nExec=/usr/local/bin/unknown\n",
            encoding="utf-8",
        )
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["installed"] is True
        assert result["owned"] is False

    def test_owned_entry_contains_codex_plugin_scanner(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["owned"] is True
        assert "codex_plugin_scanner" in desktop_path.read_text()

    # -----------------------------------------------------------------------
    # Security tests — no secrets in desktop entry
    # -----------------------------------------------------------------------

    def test_desktop_entry_contains_no_secrets(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        content = desktop_path.read_text()
        secret_patterns = [
            "password",
            "token",
            "secret",
            "apikey",
            "api_key",
            "auth",
        ]
        for pattern in secret_patterns:
            assert pattern not in content.lower(), (
                f"Desktop entry contains potential secret pattern: {pattern}"
            )

    def test_desktop_entry_reflects_run_at_login_false(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
                run_at_login=False,
            )
        content = desktop_path.read_text()
        assert "X-GNOME-Autostart-enabled=false" in content
        assert "Hidden=true" in content

    def test_desktop_entry_reflects_run_at_login_true(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
                run_at_login=True,
            )
        content = desktop_path.read_text()
        assert "X-GNOME-Autostart-enabled=true" in content
        assert "Hidden=false" in content

    # -----------------------------------------------------------------------
    # File permissions tests
    # -----------------------------------------------------------------------

    def test_desktop_entry_has_correct_permissions(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=tmp_path,
                capability=_capability(TrayPlatform.LINUX),
            )
        mode = desktop_path.stat().st_mode
        assert stat.S_IMODE(mode) == 0o644

    # -----------------------------------------------------------------------
    # Exec line with spaces in path
    # -----------------------------------------------------------------------

    def test_exec_line_quotes_paths_with_spaces(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        guard_home = tmp_path / "my guard home"  # path with spaces
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=guard_home,
                capability=_capability(TrayPlatform.LINUX),
            )
        content = desktop_path.read_text()
        for line in content.splitlines():
            if line.startswith("Exec="):
                exec_value = line[len("Exec="):]
                assert '--guard-home "' in exec_value
                assert f'"{guard_home}"' in exec_value
                break
        else:
            self.fail("No Exec= line found in desktop entry")

    def test_exec_line_quotes_paths_without_spaces(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.tray.platforms.linux import LinuxTrayAdapter

        adapter = LinuxTrayAdapter()
        desktop_path = tmp_path / "test.desktop"
        guard_home = tmp_path / "clean_path"
        with patch.object(adapter, "_desktop_path", return_value=desktop_path):
            adapter.install_registration(
                guard_home=guard_home,
                capability=_capability(TrayPlatform.LINUX),
            )
        content = desktop_path.read_text()
        for line in content.splitlines():
            if line.startswith("Exec="):
                exec_value = line[len("Exec="):]
                # Paths are always quoted, even without spaces
                assert f'"{guard_home}"' in exec_value
                break
        else:
            self.fail("No Exec= line found in desktop entry")
