"""Tests for Guard-managed shell profile PATH writes.

Regression coverage for two defects:

1. The profile writers only de-duplicated on an exact ``shim_dir`` match, so
   each distinct shim dir (one per pytest temp run) appended a fresh line to the
   shell profile. The profile accumulated dozens of stale PATH entries pointing
   at deleted temp dirs, which shadowed the real package-manager binaries.
2. Transient (temp / pytest) shim dirs were written into the long-lived shell
   profile, leaving broken entries behind after cleanup.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.shims import (
    _PACKAGE_PROFILE_MARKER,
    _is_transient_path,
    _strip_managed_marker_blocks,
    _upsert_managed_profile_block,
    activate_package_shims,
    ensure_guard_shim_path_in_shell_profile,
    ensure_package_shim_path_in_shell_profile,
    install_package_shims,
    package_shim_status,
    remove_guard_profile_blocks,
)


def _context(home: Path, guard_home: Path) -> MagicMock:
    ctx = MagicMock()
    ctx.home_dir = home
    ctx.guard_home = guard_home
    ctx.workspace_dir = None
    return ctx


@pytest.fixture(autouse=True)
def _force_zsh(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHELL", "/bin/zsh")


class TestTransientPathDetection:
    @pytest.mark.parametrize(
        "path",
        [
            "/var/folders/xx/pytest-1/guard-home/package-shims/bin",
            "/private/var/folders/yy/T/abc/guard-home/bin",
            "/tmp/guard-shims/bin",
            "/private/tmp/guard/bin",
            "/some/where/pytest-of-user/pytest-5/guard-home/package-shims/bin",
        ],
    )
    def test_transient_paths_detected(self, path: str) -> None:
        assert _is_transient_path(Path(path)) is True

    @pytest.mark.parametrize(
        "path",
        [
            str(Path.home() / ".hol-guard" / "package-shims" / "bin"),
            "/usr/local/guard/package-shims/bin",
            "/home/user/.hol-guard/bin",
        ],
    )
    def test_stable_paths_not_transient(self, path: str) -> None:
        assert _is_transient_path(Path(path)) is False

    def test_custom_tmpdir_is_transient(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A caller-pointed TMPDIR (not under /var/folders) must still be treated as transient."""
        custom = tmp_path / "scratch-tmp"
        custom.mkdir()
        monkeypatch.setenv("TMPDIR", str(custom))
        shim = custom / "guard-home" / "package-shims" / "bin"
        shim.mkdir(parents=True)
        assert _is_transient_path(shim) is True

    def test_no_windows_backslash_fragments_in_list(self) -> None:
        """The transient-fragment list is POSIX-only; backslash fragments are dead code on POSIX."""
        from codex_plugin_scanner.guard.shims import _TRANSIENT_PATH_FRAGMENTS

        assert not any("\\" in fragment for fragment in _TRANSIENT_PATH_FRAGMENTS)


class TestEnsureSkipsTransientShimDir:
    def test_package_shim_transient_dir_not_written(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        # guard_home under tmp_path -> transient on macOS (/var/folders/...).
        ctx = _context(home, tmp_path / "guard-home")
        ctx.guard_home.mkdir(parents=True)
        result = ensure_package_shim_path_in_shell_profile(ctx)
        assert result["changed"] is False
        assert result["manual_path_required"] is True
        assert not (home / ".zshrc").exists()

    def test_guard_shim_transient_dir_not_written(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        ctx = _context(home, tmp_path / "guard-home")
        ctx.guard_home.mkdir(parents=True)
        result = ensure_guard_shim_path_in_shell_profile(ctx)
        assert result["changed"] is False
        assert result["manual_path_required"] is True
        assert not (home / ".zshrc").exists()


class TestUpsertIsIdempotent:
    def test_repeat_write_does_not_accumulate_blocks(self, tmp_path: Path) -> None:
        profile = tmp_path / ".zshrc"
        export = f'{_PACKAGE_PROFILE_MARKER}\nexport PATH="/stable/shims/bin:$PATH"'
        assert _upsert_managed_profile_block(profile, export, _PACKAGE_PROFILE_MARKER)["changed"] is True
        assert _upsert_managed_profile_block(profile, export, _PACKAGE_PROFILE_MARKER)["changed"] is False
        assert profile.read_text(encoding="utf-8").count(_PACKAGE_PROFILE_MARKER) == 1

    def test_stale_block_is_replaced_not_duplicated(self, tmp_path: Path) -> None:
        profile = tmp_path / ".zshrc"
        stale = (
            f"user_alias=keep\n"
            f"{_PACKAGE_PROFILE_MARKER}\n"
            f'export PATH="/var/folders/STALE/guard-home/package-shims/bin:$PATH"\n'
            f"other_setting=1\n"
        )
        profile.write_text(stale, encoding="utf-8")
        fresh = f'{_PACKAGE_PROFILE_MARKER}\nexport PATH="/stable/shims/bin:$PATH"'
        assert _upsert_managed_profile_block(profile, fresh, _PACKAGE_PROFILE_MARKER)["changed"] is True
        text = profile.read_text(encoding="utf-8")
        assert text.count(_PACKAGE_PROFILE_MARKER) == 1
        assert "STALE" not in text
        assert "/stable/shims/bin" in text
        # User content outside the managed block is preserved.
        assert "user_alias=keep" in text
        assert "other_setting=1" in text

    def test_multiple_stale_blocks_collapsed_to_one(self, tmp_path: Path) -> None:
        profile = tmp_path / ".zshrc"
        polluted = (
            "\n".join(
                f'{_PACKAGE_PROFILE_MARKER}\nexport PATH="/var/folders/pytest-{i}/guard-home/package-shims/bin:$PATH"'
                for i in range(5)
            )
            + "\n"
        )
        profile.write_text(polluted, encoding="utf-8")
        fresh = f'{_PACKAGE_PROFILE_MARKER}\nexport PATH="/stable/shims/bin:$PATH"'
        _upsert_managed_profile_block(profile, fresh, _PACKAGE_PROFILE_MARKER)
        text = profile.read_text(encoding="utf-8")
        assert text.count(_PACKAGE_PROFILE_MARKER) == 1
        assert "pytest-" not in text


class TestStripManagedMarkerBlocks:
    def test_preserves_unrelated_marker_free_content(self) -> None:
        content = "a=1\nb=2\n"
        assert _strip_managed_marker_blocks(content, _PACKAGE_PROFILE_MARKER) == content

    def test_empty_content_stays_empty(self) -> None:
        assert _strip_managed_marker_blocks("", _PACKAGE_PROFILE_MARKER) == ""

    def test_user_triple_blank_lines_preserved(self) -> None:
        """Stripping must only drop blank lines adjacent to a removed block; user blanks stay intact."""
        content = "a=1\n\n\n\nb=2\n"  # 3 blank lines between user content
        assert _strip_managed_marker_blocks(content, _PACKAGE_PROFILE_MARKER) == content


class TestEnsureWritesStablePath:
    def test_package_shim_writes_single_stable_entry(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        home.mkdir()
        guard_home = tmp_path / "guard-home"
        (guard_home / "package-shims" / "bin").mkdir(parents=True)
        ctx = _context(home, guard_home)
        # Force the shim dir to look stable so the writer proceeds under a temp home.
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.shims._is_transient_path",
            lambda path: False,
        )
        ensure_package_shim_path_in_shell_profile(ctx)
        ensure_package_shim_path_in_shell_profile(ctx)
        text = (home / ".zshrc").read_text(encoding="utf-8")
        assert text.count(_PACKAGE_PROFILE_MARKER) == 1
        assert "package-shims/bin" in text

    def test_package_shim_path_works_in_bash_interactive_and_login_shells(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A zsh login shell must not leave Bash package commands unprotected."""

        home = tmp_path / "home"
        home.mkdir()
        guard_home = home / ".hol-guard"
        context = _context(home, guard_home)
        bash_login_profile = home / ".bash_profile"
        bash_login_profile.write_text("export KEEP_LOGIN=1\n", encoding="utf-8")
        monkeypatch.setenv("SHELL", "/bin/zsh")
        monkeypatch.setattr("codex_plugin_scanner.guard.shims._is_transient_path", lambda _path: False)
        install_package_shims(context, managers=("npm",))
        result = ensure_package_shim_path_in_shell_profile(context)
        shim_path = guard_home / "package-shims" / "bin" / "npm"

        assert result["profile_path"] == str(home / ".zshrc")
        assert set(result["profile_paths"]) == {
            str(home / ".zshrc"),
            str(home / ".bashrc"),
            str(home / ".bash_profile"),
        }
        assert (home / ".bashrc").read_text(encoding="utf-8").count(_PACKAGE_PROFILE_MARKER) == 1
        assert "export KEEP_LOGIN=1" in bash_login_profile.read_text(encoding="utf-8")
        assert bash_login_profile.read_text(encoding="utf-8").count(_PACKAGE_PROFILE_MARKER) == 1

        shell_env = dict(os.environ)
        shell_env["HOME"] = str(home)
        shell_env["PATH"] = os.environ.get("PATH", "")
        interactive = subprocess.run(
            ["bash", "--noprofile", "--norc", "-ic", 'source "$HOME/.bashrc"; command -v npm'],
            capture_output=True,
            check=True,
            env=shell_env,
            text=True,
        )
        login = subprocess.run(
            ["bash", "-lc", "command -v npm"],
            capture_output=True,
            check=True,
            env=shell_env,
            text=True,
        )

        assert Path(interactive.stdout.strip()) == shim_path
        assert Path(login.stdout.strip()) == shim_path
        status = package_shim_status(context)
        assert status["process_path_status"] == "profile_staged"
        assert status["shell_profile_paths"] == [
            str(home / ".zshrc"),
            str(home / ".bashrc"),
            str(home / ".bash_profile"),
        ]

    def test_partial_profile_migration_stays_repairable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        home.mkdir()
        guard_home = home / ".hol-guard"
        context = _context(home, guard_home)
        monkeypatch.setenv("SHELL", "/bin/zsh")
        monkeypatch.setattr("codex_plugin_scanner.guard.shims._is_transient_path", lambda _path: False)
        install_package_shims(context, managers=("npm",))
        shim_dir = guard_home / "package-shims" / "bin"
        (home / ".zshrc").write_text(
            f'{_PACKAGE_PROFILE_MARKER}\nexport PATH="{shim_dir}:$PATH"\n',
            encoding="utf-8",
        )

        before = package_shim_status(context)

        assert before["shell_profile_configured"] is False
        assert before["process_path_status"] == "missing"
        assert before["shell_profile_paths"] == [str(home / ".zshrc")]
        assert before["shell_profile_missing_paths"] == [
            str(home / ".bashrc"),
            str(home / ".profile"),
        ]

        repaired = activate_package_shims(context, managers=("npm",), repair=True)

        assert repaired["activation_state"] == "restart_required"
        after = package_shim_status(context)
        assert after["shell_profile_configured"] is True
        assert after["process_path_status"] == "profile_staged"
        assert after["shell_profile_missing_paths"] == []

    def test_hostile_guard_home_path_is_literal_in_bash_profiles(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        home = tmp_path / "home"
        home.mkdir()
        sentinel = tmp_path / "shim-injection-ran"
        guard_home = home / "guard 'quoted' $(touch shim-injection-ran) \\ suffix"
        context = _context(home, guard_home)
        (home / ".bash_profile").write_text("export KEEP_LOGIN=1\n", encoding="utf-8")
        monkeypatch.setenv("SHELL", "/bin/zsh")
        monkeypatch.setattr("codex_plugin_scanner.guard.shims._is_transient_path", lambda _path: False)
        install_package_shims(context, managers=("npm",))
        ensure_package_shim_path_in_shell_profile(context)
        shim_path = guard_home / "package-shims" / "bin" / "npm"

        shell_env = dict(os.environ)
        shell_env["HOME"] = str(home)
        shell_env["PATH"] = os.environ.get("PATH", "")
        interactive = subprocess.run(
            ["bash", "--noprofile", "--norc", "-ic", 'source "$HOME/.bashrc"; command -v npm'],
            capture_output=True,
            check=True,
            cwd=tmp_path,
            env=shell_env,
            text=True,
        )
        login = subprocess.run(
            ["bash", "-lc", "command -v npm"],
            capture_output=True,
            check=True,
            cwd=tmp_path,
            env=shell_env,
            text=True,
        )

        assert not sentinel.exists()
        assert Path(interactive.stdout.strip()) == shim_path
        assert Path(login.stdout.strip()) == shim_path
        status = package_shim_status(context)
        assert status["shell_profile_configured"] is True
        assert status["process_path_status"] == "profile_staged"
        assert status["shell_profile_missing_paths"] == []

    def test_hostile_guard_home_path_is_quoted_for_fish(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        home = tmp_path / "home"
        home.mkdir()
        guard_home = home / "guard 'quoted' $(printf unsafe) \\ suffix"
        context = _context(home, guard_home)
        monkeypatch.setenv("SHELL", "/usr/bin/fish")
        monkeypatch.setattr("codex_plugin_scanner.guard.shims._is_transient_path", lambda _path: False)

        ensure_package_shim_path_in_shell_profile(context)

        fish_profile = home / ".config" / "fish" / "config.fish"
        expected = f"fish_add_path --prepend -- {shlex.quote(str(guard_home / 'package-shims' / 'bin'))}"
        assert expected in fish_profile.read_text(encoding="utf-8")
        status = package_shim_status(context)
        assert status["shell_profile_configured"] is True
        assert status["shell_profile_missing_paths"] == []


class TestEnsureSkipsOnWindows:
    """Both profile writers must short-circuit on Windows before touching .zshrc."""

    def _stable_ctx(self, tmp_path: Path) -> MagicMock:
        home = tmp_path / "home"
        home.mkdir()
        guard_home = home / ".hol-guard"
        (guard_home / "bin").mkdir(parents=True)
        (guard_home / "package-shims" / "bin").mkdir(parents=True)
        return _context(home, guard_home)

    def test_package_shim_skipped_on_windows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = self._stable_ctx(tmp_path)
        monkeypatch.setattr("codex_plugin_scanner.guard.shims.os.name", "nt")
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.shims._is_transient_path",
            lambda path: False,
        )
        result = ensure_package_shim_path_in_shell_profile(ctx)
        assert result["changed"] is False
        assert result["manual_path_required"] is True
        assert not (ctx.home_dir / ".zshrc").exists()

    def test_guard_shim_skipped_on_windows(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = self._stable_ctx(tmp_path)
        monkeypatch.setattr("codex_plugin_scanner.guard.shims.os.name", "nt")
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.shims._is_transient_path",
            lambda path: False,
        )
        result = ensure_guard_shim_path_in_shell_profile(ctx)
        assert result["changed"] is False
        assert result["manual_path_required"] is True
        assert not (ctx.home_dir / ".zshrc").exists()


class TestRemoveGuardProfileBlocks:
    def test_removes_guard_markers_across_common_shell_profiles(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        home.mkdir()
        fish_config = home / ".config" / "fish" / "config.fish"
        bash_profile = home / ".bashrc"
        zsh_profile = home / ".zshrc"
        bash_profile.write_text(
            "\n".join(
                [
                    "export KEEP=1",
                    "# HOL Guard harness launchers",
                    'export PATH="/tmp/guard-home/bin:$PATH"',
                    "",
                ]
            ),
            encoding="utf-8",
        )
        zsh_profile.write_text(
            "\n".join(
                [
                    "# HOL Guard package manager shims",
                    'export PATH="/tmp/guard-home/package-shims/bin:$PATH"',
                    "alias ll='ls -l'",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        fish_config.parent.mkdir(parents=True, exist_ok=True)
        fish_config.write_text(
            "# HOL Guard harness launchers\nfish_add_path --prepend /tmp/guard-home/bin\n",
            encoding="utf-8",
        )

        result = remove_guard_profile_blocks(_context(home, home / ".hol-guard"))

        assert result["changed"] is True
        assert sorted(Path(path).name for path in result["changed_paths"]) == [
            ".bashrc",
            ".zshrc",
            "config.fish",
        ]
        assert Path(fish_config) == Path(result["removed_paths"][0])
        assert "# HOL Guard" not in bash_profile.read_text(encoding="utf-8")
        assert bash_profile.read_text(encoding="utf-8") == "export KEEP=1\n"
        assert "# HOL Guard" not in zsh_profile.read_text(encoding="utf-8")
        assert "alias ll='ls -l'" in zsh_profile.read_text(encoding="utf-8")
        assert not fish_config.exists()
