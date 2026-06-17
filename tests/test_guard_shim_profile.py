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

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.shims import (
    _PACKAGE_PROFILE_MARKER,
    _is_transient_path,
    _strip_managed_marker_blocks,
    _upsert_managed_profile_block,
    ensure_guard_shim_path_in_shell_profile,
    ensure_package_shim_path_in_shell_profile,
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
