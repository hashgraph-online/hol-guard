"""Tests for daemon-startup harness shim refresh."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from codex_plugin_scanner.guard.shim_refresh import (
    _existing_shim_harnesses,
    _launcher_map,
    refresh_stale_harness_shims,
)
from codex_plugin_scanner.guard.shims import _build_python_shim, install_guard_shim


class _Context:
    def __init__(self, home_dir: Path, guard_home: Path, workspace_dir: Path | None = None) -> None:
        self.home_dir = home_dir
        self.workspace_dir = workspace_dir
        self.guard_home = guard_home
        self.home_override_explicit = False


class ShimRefreshTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.home_dir = root / "home"
        self.home_dir.mkdir()
        self.guard_home = root / "home" / ".hol-guard"
        self.guard_home.mkdir(parents=True)

    def _context(self, workspace_dir: Path | None = None) -> _Context:
        return _Context(self.home_dir, self.guard_home, workspace_dir)

    def _install(self, harness: str, workspace_dir: Path | None = None) -> Path:
        install_guard_shim(harness, self._context(workspace_dir))
        return self.guard_home / "bin" / f"guard-{harness}"

    def test_launcher_map_resolves_legacy_names(self) -> None:
        mapping = _launcher_map()
        self.assertEqual(mapping["claude"], ("claude-code", "claude"))
        self.assertEqual(mapping["claude-code"], ("claude-code", "claude"))
        self.assertEqual(mapping["cursor-agent"], ("cursor", "cursor-agent"))
        self.assertEqual(mapping["cursor"], ("cursor", "cursor-agent"))
        self.assertEqual(mapping["kimi"], ("kimi", "kimi"))

    def test_existing_shims_skip_cmd_and_non_guard_files(self) -> None:
        shim_dir = self.guard_home / "bin"
        shim_dir.mkdir()
        (shim_dir / "guard-kimi").write_text("x", encoding="utf-8")
        (shim_dir / "guard-kimi.cmd").write_text("x", encoding="utf-8")
        (shim_dir / "other").write_text("x", encoding="utf-8")
        self.assertEqual(_existing_shim_harnesses(shim_dir), ["kimi"])

    def test_current_shim_is_left_unchanged(self) -> None:
        self._install("kimi")
        result = refresh_stale_harness_shims(
            home_dir=self.home_dir,
            guard_home=self.guard_home,
            managed_installs=[],
        )
        self.assertEqual(result.refreshed, ())
        self.assertEqual(result.unchanged, ("kimi",))
        self.assertEqual(result.errors, ())

    def test_appimage_shell_shim_is_recognized_and_left_unchanged(self) -> None:
        with mock.patch(
            "codex_plugin_scanner.guard.shims.sys.executable",
            "/tmp/.mount_HOLGUARD/usr/lib/hol-guard-core/hol-guard",
        ):
            path = self._install("kimi")
            result = refresh_stale_harness_shims(
                home_dir=self.home_dir,
                guard_home=self.guard_home,
                managed_installs=[],
            )
        self.assertTrue(path.read_text(encoding="utf-8").startswith("#!/bin/sh\n# base_command = "))
        self.assertEqual(result.refreshed, ())
        self.assertEqual(result.unchanged, ("kimi",))
        self.assertEqual(result.errors, ())

    @unittest.skipIf(sys.platform == "win32", "POSIX harness launcher contract")
    def test_frozen_desktop_refresh_uses_stable_desktop_cli(self) -> None:
        official_cli = self.home_dir / ".local" / "bin" / "hol-guard"
        official_cli.parent.mkdir(parents=True)
        official_cli.write_text("#!/bin/sh\nexit 98\n", encoding="utf-8")
        official_cli.chmod(0o755)
        capture_path = self.home_dir / "captured-args"
        desktop_root = self.home_dir / "desktop" / "core"
        stable_cli = desktop_root / "current-hol-guard"
        stable_cli.parent.mkdir(parents=True)
        stable_cli.write_text(
            f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {str(capture_path)!r}\n",
            encoding="utf-8",
        )
        stable_cli.chmod(0o755)
        desktop_owner = desktop_root / "bundled" / "3.0.63" / "bin" / "hol-guard"
        desktop_owner.parent.mkdir(parents=True)
        desktop_owner.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        desktop_owner.chmod(0o755)

        with (
            mock.patch("codex_plugin_scanner.guard.shims.sys.frozen", False, create=True),
            mock.patch("codex_plugin_scanner.guard.shims.sys.executable", str(desktop_owner)),
        ):
            path = self._install("kimi")
        self.assertTrue(path.read_text(encoding="utf-8").startswith(f"#!{desktop_owner}\n"))

        with (
            mock.patch("codex_plugin_scanner.guard.shims.sys.frozen", True, create=True),
            mock.patch("codex_plugin_scanner.guard.shims.sys.executable", str(desktop_owner)),
            mock.patch(
                "codex_plugin_scanner.guard.shims._is_transient_path",
                side_effect=lambda path: ".mount_" in str(path),
            ),
            mock.patch.dict(
                "codex_plugin_scanner.guard.durable_harness_launcher.os.environ",
                {"HOL_GUARD_DESKTOP_RUNTIME_OWNER": str(desktop_owner)},
                clear=False,
            ),
        ):
            result = refresh_stale_harness_shims(
                home_dir=self.home_dir,
                guard_home=self.guard_home,
                managed_installs=[],
            )
            completed = subprocess.run([str(path), "--help"], check=False)

        self.assertEqual(result.refreshed, ("kimi",))
        self.assertEqual(completed.returncode, 0)
        self.assertTrue(path.read_text(encoding="utf-8").startswith("#!/bin/sh\n"))
        windows_source = path.with_suffix(".cmd").read_text(encoding="utf-8")
        self.assertIn("run-shim", windows_source)
        self.assertIn(str(stable_cli), windows_source)
        self.assertNotIn(str(path), windows_source)
        self.assertIn('"--" %*', windows_source)
        self.assertEqual(
            capture_path.read_text(encoding="utf-8").splitlines(),
            [
                "run",
                "kimi",
                "--guard-home",
                str(self.guard_home),
                "--home",
                str(self.home_dir),
                "--arg=--help",
            ],
        )

    @unittest.skipIf(sys.platform == "win32", "POSIX harness launcher contract")
    def test_frozen_durable_runtime_remains_a_launcher_fallback(self) -> None:
        capture_path = self.home_dir / "captured-args"
        runtime = self.home_dir / "Applications" / "HOL Guard.app" / "Contents" / "MacOS" / "hol-guard"
        runtime.parent.mkdir(parents=True)
        runtime.write_text(
            f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {str(capture_path)!r}\n",
            encoding="utf-8",
        )
        runtime.chmod(0o755)

        with (
            mock.patch("codex_plugin_scanner.guard.shims.sys.frozen", True, create=True),
            mock.patch("codex_plugin_scanner.guard.shims.sys.executable", str(runtime)),
            mock.patch(
                "codex_plugin_scanner.guard.shims._is_transient_path",
                side_effect=lambda path: ".mount_" in str(path),
            ),
            mock.patch.dict(
                "codex_plugin_scanner.guard.durable_harness_launcher.os.environ",
                {"HOL_GUARD_DESKTOP_RUNTIME_OWNER": ""},
                clear=False,
            ),
        ):
            path = self._install("kimi")
            completed = subprocess.run([str(path), "--version"], check=False)

        self.assertEqual(completed.returncode, 0)
        self.assertIn(str(runtime), path.read_text(encoding="utf-8"))
        self.assertEqual(
            capture_path.read_text(encoding="utf-8").splitlines()[-1],
            "--arg=--version",
        )

    def test_stale_shim_is_refreshed_with_current_generator_content(self) -> None:
        path = self._install("kimi")
        # Drift a real generated shim (keeps base_command parseable).
        path.write_text(path.read_text(encoding="utf-8") + "\n# drifted\n", encoding="utf-8")
        result = refresh_stale_harness_shims(
            home_dir=self.home_dir,
            guard_home=self.guard_home,
            managed_installs=[],
        )
        self.assertEqual(result.refreshed, ("kimi",))
        self.assertEqual(result.errors, ())
        expected = _build_python_shim("kimi", self._context(), [])
        self.assertEqual(path.read_text(encoding="utf-8"), expected)

    def test_workspace_binding_is_preserved_from_managed_installs(self) -> None:
        workspace = self.home_dir / "project"
        workspace.mkdir()
        path = self._install("kimi", workspace)
        original = path.read_text(encoding="utf-8")
        self.assertIn("--workspace", original)
        # Force staleness while keeping the workspace binding.
        path.write_text(original.replace("kimi", "kimi", 1) + "\n# drifted\n", encoding="utf-8")
        result = refresh_stale_harness_shims(
            home_dir=self.home_dir,
            guard_home=self.guard_home,
            managed_installs=[
                {"harness": "kimi", "active": True, "workspace": str(workspace), "manifest": {}, "updated_at": ""}
            ],
        )
        self.assertEqual(result.refreshed, ("kimi",))
        self.assertEqual(result.errors, ())
        refreshed = path.read_text(encoding="utf-8")
        self.assertIn("--workspace", refreshed)
        self.assertIn(str(workspace), refreshed)

    def test_legacy_launcher_is_canonicalized_and_removed(self) -> None:
        shim_dir = self.guard_home / "bin"
        shim_dir.mkdir()
        # Write a real cursor shim under the legacy launcher name.
        body = _build_python_shim("cursor", self._context(), [])
        legacy = shim_dir / "guard-cursor"
        legacy.write_text(body, encoding="utf-8")
        legacy.chmod(0o755)
        legacy_cmd = shim_dir / "guard-cursor.cmd"
        legacy_cmd.write_text("@echo off\n", encoding="utf-8")
        result = refresh_stale_harness_shims(
            home_dir=self.home_dir,
            guard_home=self.guard_home,
            managed_installs=[],
        )
        self.assertEqual(result.refreshed, ("cursor",))
        self.assertEqual(result.errors, ())
        canonical = shim_dir / "guard-cursor-agent"
        self.assertTrue(canonical.is_file())
        self.assertIn("cursor", canonical.read_text(encoding="utf-8"))
        self.assertFalse(legacy.exists())
        self.assertFalse(legacy_cmd.exists())
        # Second pass: canonical shim is current, nothing left to refresh.
        second = refresh_stale_harness_shims(
            home_dir=self.home_dir,
            guard_home=self.guard_home,
            managed_installs=[],
        )
        self.assertEqual(second.refreshed, ())
        self.assertEqual(second.unchanged, ("cursor-agent",))

    def test_custom_home_binding_is_preserved(self) -> None:
        context = _Context(self.home_dir, self.guard_home)
        context.home_override_explicit = True
        install_guard_shim("kimi", context)
        path = self.guard_home / "bin" / "guard-kimi"
        original = path.read_text(encoding="utf-8")
        self.assertIn("--home", original)
        path.write_text(original + "\n# drifted\n", encoding="utf-8")
        result = refresh_stale_harness_shims(
            home_dir=self.home_dir,
            guard_home=self.guard_home,
            managed_installs=[],
        )
        self.assertEqual(result.refreshed, ("kimi",))
        self.assertEqual(result.errors, ())
        refreshed = path.read_text(encoding="utf-8")
        self.assertIn("--home", refreshed)
        self.assertIn(str(self.home_dir), refreshed)

    def test_legacy_canonical_coexistence_keeps_canonical_context(self) -> None:
        shim_dir = self.guard_home / "bin"
        shim_dir.mkdir()
        workspace = self.home_dir / "project"
        workspace.mkdir()
        # Canonical shim carries a workspace binding; legacy has none.
        canonical_body = _build_python_shim("cursor", self._context(workspace), ["--workspace", str(workspace)])
        canonical = shim_dir / "guard-cursor-agent"
        canonical.write_text(canonical_body, encoding="utf-8")
        canonical.chmod(0o755)
        legacy_body = _build_python_shim("cursor", self._context(), [])
        legacy = shim_dir / "guard-cursor"
        legacy.write_text(legacy_body, encoding="utf-8")
        legacy.chmod(0o755)
        result = refresh_stale_harness_shims(
            home_dir=self.home_dir,
            guard_home=self.guard_home,
            managed_installs=[],
        )
        self.assertEqual(sorted(result.refreshed), ["cursor"])
        self.assertEqual(result.errors, ())
        self.assertFalse(legacy.exists())
        # Canonical content untouched: workspace binding preserved byte-for-byte.
        self.assertEqual(canonical.read_text(encoding="utf-8"), canonical_body)

    def test_unknown_shim_is_left_alone(self) -> None:
        shim_dir = self.guard_home / "bin"
        shim_dir.mkdir()
        (shim_dir / "guard-retired-harness").write_text("x", encoding="utf-8")
        result = refresh_stale_harness_shims(
            home_dir=self.home_dir,
            guard_home=self.guard_home,
            managed_installs=[],
        )
        self.assertEqual(result.refreshed, ())
        self.assertEqual(result.unchanged, ("retired-harness",))
        self.assertEqual(result.errors, ())


if __name__ == "__main__":
    unittest.main()
